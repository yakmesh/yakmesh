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
import crypto from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { networkInterfaces } from 'os';
import { WebSocketServer } from 'ws';
import { createLogger } from '../utils/logger.js';
import * as accel from '../utils/accel.js';
import { startPipeServer, getPipePath, upgradePipeAntiCheat, isPipeServerRunning } from '../utils/scheduler-pipe.js';
import * as prahari from '../security/prahari.js';
import { registerGPSJitterWithPrahari } from '../security/sources/gps-jitter.js';
import { registerMeshEntropyWithPrahari, wireCommitReveal } from '../security/prahari-mesh.js';
import { wireAguwaWithPrahari } from '../security/prahari-aguwa.js';

// Backward compat alias — all internal references now use 'prahari'
const steadywatch = prahari;

// Embedded Caddy web server for HTTPS/443 reverse proxy
import { YakmeshWebServer } from '../webserver/index.js';

const log = createLogger('server:main');
const peerTag = (id) => id?.split('-pq-').pop() || id?.slice?.(-8) || String(id);
import { NodeIdentity } from '../identity/node-key.js';
import { MeshNetwork } from '../mesh/network.js';
import { YakTun } from '../mesh/tun.js';
import { ReplicationEngine } from '../database/replication.js';
import { GossipProtocol } from '../gossip/protocol.js';

// Content store for public delivery
import { ContentStore, createContentAPI } from '../content/index.js';

// Embedded documentation (hardcoded, hash-verified)
import { getDocsFile, serveDocsFile, getBundleInfo } from '../embedded-docs/index.js';

// Annex lives in mesh/network.js — single instance, no duplication
// ServerAnnexSession for client-facing WS (KOMM channel encryption)
import { ServerAnnexSession, ANNEX_HANDSHAKE_TYPE } from './crypto/annex.js';

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
  onTamper,
  getTamperEvents,
} from '../oracle/index.js';

// Time source imports
import {
  TimeSourceDetector,
  getTimeSourceDetector,
  createPhaseConfig,
  detectTimeSources,
} from '../oracle/time-source.js';
import { setTimeSourceConfig, getActiveConfig, getCurrentEpoch, getEpochStartTime } from '../oracle/phase-epoch.js';
import { aguwa } from '../mesh/aguwa.js';

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

// PROFILE — Unified mesh-distributed user profiles
import { createProfileAPI, wireProfileGossip, ensureProfileTable } from './profile-api.js';

// TME — Temporal Mesh Encoding (time-based packet resilience)
import { createTmeAPI, wireTmeGossip } from './tme-api.js';
import { wireTmeTransport } from '../mesh/tme-transport.js';

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

// SANGHA — Unified Component Attestation (collective security)
import { getSangha, joinSangha, SANGHA_COMPONENT } from '../security/sangha.js';

// FS Hardening — File integrity with SANGHA-FS integration
import { getFSHardening, PROTECTION_LEVEL } from '../security/fs-hardening.js';

// Memory Safety — Circulating canaries for memory integrity
import { getMemorySafety } from '../security/memory-safety.js';

// SERVER DIRECTORY — C2C Lighthouse (server browser via gossip heartbeats)
import ServerDirectory from '../mesh/server-directory.js';

// Temporal Signing — GPS-bound code signatures with auto-expiry
import { getTemporalSigner, TemporalSignature } from '../security/temporal-signing.js';

// KARMA Rate Limiter — KARMA-adaptive rate limiting with input validation
import { getKarmaRateLimiter, KARMA_TIERS, SIZE_LIMITS } from '../security/karma-rate-limiter.js';

// Secure Config — Oracle-attested configuration management
import { getSecureConfig, PROFILE_LEVEL, SECURE_DEFAULTS } from '../security/secure-config.js';

// TRIBHUJ — Balanced ternary for KARMA trit mapping
import { POSITIVE, NEUTRAL, NEGATIVE, TritState } from '../oracle/tribhuj.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TERNARY HARMONIZATION — SST × YPC-27 × 162T × ML
// ═══════════════════════════════════════════════════════════════════════════════

// YPC27_SST — SST seed rotation for YPC-27 checksums
import { YPC27_SST } from '../oracle/ypc27.js';

// Batch checksum verification (GPU-accelerated)
import { batchChecksumVerifier, BatchChecksumVerifier } from '../oracle/packet-checksum.js';

// Ternary ML — quantized inference & trust classification
import { TernaryInferenceAdapter } from '../oracle/ternary-ml.js';

// 162T — Hierarchical ternary mesh addressing
import { TritAddress, TernaryRoutingTable, hexIdToAddress, TierName } from '../oracle/ternary-routing.js';

// Time API — HTTP bridge to MA-902 GPS time server (serves on port 3099)
import { startTimeApi, stopTimeApi } from '../oracle/time-api.js';

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

// Read canonical ports from config/ports.json (single source of truth)
let _defaultPorts = { httpPort: 3080, wsPort: 9080 };
try {
  _defaultPorts = JSON.parse(readFileSync(join(import.meta.dirname || '.', '..', 'config', 'ports.json'), 'utf8'));
} catch { /* use hardcoded fallback */ }

// Default config
const DEFAULT_CONFIG = {
  node: {
    name: 'Yakmesh Node',
    region: 'local',
  },
  network: {
    httpPort: _defaultPorts.httpPort,
    wsPort: _defaultPorts.wsPort,
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
 * Load configuration.
 * 
 * SECURITY: Config MUST be loaded from the codebase-local yakmesh.config.js.
 * The Validation Oracle hashes ALL .js files — config included — so any node
 * loading a different config file would compute a different genesis hash and
 * be rejected by the mesh.  Never allow runtime config file injection.
 * 
 * Resolution order:
 *   1. CLI argument: --config <path>  (for production deployments)
 *   2. Default: ./yakmesh.config.js   (byte-identical on every node)
 * 
 * Runtime overrides via env vars (applied AFTER config load, never touch files):
 *   YAKMESH_HTTP_PORT   — override network.httpPort
 *   YAKMESH_WS_PORT     — override network.wsPort
 *   YAKMESH_DATA_DIR    — override database.path directory
 *   YAKMESH_BOOTSTRAP   — override bootstrap peer list (comma-separated ws:// URLs)
 *   YAKMESH_RELAY_PEERS  — auto-register with relay endpoints at startup (comma-separated https:// URLs)
 */
async function loadConfig() {
  // 1. Check for --config CLI argument (operator-controlled, not env-injectable)
  const configArgIndex = process.argv.findIndex(arg => arg === '--config' || arg === '-c');
  let configPath = './yakmesh.config.js';

  if (configArgIndex !== -1 && process.argv[configArgIndex + 1]) {
    configPath = process.argv[configArgIndex + 1];
    log.info(`📋 Config source: CLI --config ${configPath}`);
  }

  let config = { ...DEFAULT_CONFIG };

  // Load config from the resolved path
  if (existsSync(configPath)) {
    // Handle both absolute and relative paths
    const isAbsolute = configPath.startsWith('/') || /^[A-Z]:/i.test(configPath);
    const importPath = isAbsolute
      ? `file://${configPath.replace(/\\/g, '/')}`
      : `../${configPath.replace('./', '')}`;
    const { default: userConfig } = await import(importPath);
    config = { ...DEFAULT_CONFIG, ...userConfig };
  } else {
    log.warn(`⚠️ Config file not found: ${configPath} — using defaults`);
  }

  // Apply env var overrides (allows multi-node on same machine
  // WITHOUT modifying the config file — config MUST stay byte-identical
  // for oracle hash integrity)
  if (process.env.YAKMESH_HTTP_PORT) {
    config.network = { ...config.network, httpPort: parseInt(process.env.YAKMESH_HTTP_PORT, 10) };
  }
  if (process.env.YAKMESH_WS_PORT) {
    config.network = { ...config.network, wsPort: parseInt(process.env.YAKMESH_WS_PORT, 10) };
  }
  if (process.env.YAKMESH_DATA_DIR) {
    config.database = { ...config.database, path: `${process.env.YAKMESH_DATA_DIR}/yakmesh.db` };
  }
  if (process.env.YAKMESH_BOOTSTRAP) {
    // Comma-separated WS URLs, e.g. ws://localhost:9011,ws://localhost:9012
    config.bootstrap = process.env.YAKMESH_BOOTSTRAP
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
  }

  if (process.env.YAKMESH_RELAY_PEERS) {
    // Comma-separated HTTPS relay URLs, e.g. https://yakmesh.dev/mesh/relay.php
    config.relayPeers = process.env.YAKMESH_RELAY_PEERS
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
  }

  // Caddy web server config (HTTPS/443 reverse proxy)
  // YAKMESH_DOMAIN=yakmesh.dev enables auto-HTTPS via Let's Encrypt
  // YAKMESH_ACME_EMAIL=admin@yakmesh.dev for cert notifications
  if (process.env.YAKMESH_DOMAIN) {
    config.caddy = {
      enabled: true,
      domain: process.env.YAKMESH_DOMAIN,
      autoHttps: true,
      acmeEmail: process.env.YAKMESH_ACME_EMAIL || null,
      nodeHttpPort: config.network?.httpPort || 3080,
      nodeWsPort: config.network?.wsPort || 9080,
    };
  }

  return config;
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

    // SANGHA — collective component attestation
    this.sangha = null;

    // FS Hardening — file integrity with SANGHA-FS
    this.fsHardening = null;

    // Memory Safety — circulating canaries
    this.memorySafety = null;

    // SERVER DIRECTORY — C2C Lighthouse (aggregated heartbeats)
    this.serverDirectory = null;

    // Temporal Signing — GPS-bound code signatures
    this.temporalSigner = null;

    // KARMA Rate Limiter — adaptive rate limiting
    this.rateLimiter = null;

    // Secure Config — oracle-attested configuration
    this.secureConfig = null;

    // Codebase lock status
    this.codebaseLocked = false;
  }

  async start() {
    log.info('\n🦬 Starting Yakmesh Node...\n');

    // Record start time for uptime tracking
    this._startTime = aguwa.now();

    // 0. LOCK THE CODEBASE - Prevent any modifications during runtime
    // This is critical for Code Proof Protocol security
    log.info('🔐 Securing codebase...');
    const lockResult = lockCodebase();
    if (lockResult.success) {
      this.codebaseLocked = true;
      setupUnlockOnExit();  // Ensure cleanup on process exit
      log.info(`✓ Codebase locked: ${lockResult.fileCount} source files protected`);

      // Subscribe to tampering events
      onTamper((event) => {
        log.error('🚨 SECURITY ALERT: Tampering detected!', {
          type: event.type,
          path: event.path,
          time: event.isoTime,
        });
        // Could broadcast to mesh here for visibility
      });

      if (lockResult.watchdogActive) {
        log.info('✓ Watchdog active: monitoring for tampering attempts');
      }
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

    // 0b½. Load ONNX models — NPU/GPU-accelerated security inference
    // These models are used by EntropySentinel, SAKSHI, and KARMA subsystems.
    // If onnxruntime-node is not installed, loadModel silently returns false
    // and all subsystems fall back to CPU-only heuristic paths.
    const modelsDir = join(import.meta.dirname, '..', 'models');
    const ONNX_MODELS = [
      { name: 'entropy-sentinel', file: 'entropy-sentinel.onnx' },
      { name: 'sakshi-anomaly', file: 'sakshi-anomaly.onnx' },
      { name: 'karma-trust', file: 'karma-trust.onnx' },
    ];
    let modelsLoaded = 0;
    for (const { name, file } of ONNX_MODELS) {
      const modelPath = join(modelsDir, file);
      if (existsSync(modelPath)) {
        const ok = await accel.inference.loadModel(name, modelPath);
        if (ok) modelsLoaded++;
      }
    }
    if (modelsLoaded > 0) {
      log.info(`✓ ONNX models: ${modelsLoaded}/${ONNX_MODELS.length} loaded (${accel.inference._preferredProvider || 'CPU'})`);
    } else {
      log.info('○ ONNX models: none loaded (CPU heuristic fallback active)');
    }

    // 0b¾. Start Scheduler Pipe — cross-process compute coordination
    // Named pipe server lets c2c/yakai request routing advice from the
    // ComputeScheduler without HTTP overhead (~50μs vs ~2-8ms).
    try {
      const pipeResult = await startPipeServer({ accel, log });
      if (pipeResult.listening) {
        log.info(`✓ Scheduler pipe: ${pipeResult.path}`);
      } else {
        log.info('○ Scheduler pipe: not started (port in use or unavailable)');
      }
    } catch (err) {
      log.warn(`⚠️ Scheduler pipe failed: ${err.message} — c2c will use standalone mode`);
    }

    // 0c. Initialize PRAHARI v3 — Pure Sponge Entropy Engine
    // Two-source extractor: sponge_squeeze ⊕ CSPRNG → hybrid entropy.
    // Built-in sources: CPU interrupt jitter + CSPRNG. GPS jitter + mesh arrival register later.
    log.info('🛡️  Initializing PRAHARI v3 (sponge entropy)...');
    const prahariResult = await prahari.initialize({
      seedFile: this.config.prahari?.seedFile || this.config.steadywatch?.seedFile,
      inferenceEngine: accel.inference,
    });
    if (prahariResult.initialized) {
      log.info(`✓ PRAHARI v3: Sponge engine ready (Sentinel: ${prahariResult.sentinel ? 'NPU' : 'CPU'})`);
    } else {
      log.warn('⚠️  PRAHARI: sponge not initialized, ANNEX will use pure CSPRNG');
    }

    // 1. Initialize the Oracle system FIRST (provides codebase hash for identity)
    // This MUST happen before identity initialization
    this._initOracle();

    // 1a. Initialize AGUWA with oracle hash — derives Kuramoto natural frequency
    //     Same codebase hash → same ω → guaranteed phase-lock between nodes
    if (this.oracle?.selfHash) {
      aguwa.init(this.oracle.selfHash);
    }

    // 1a'. Initialize PeerPhaseBuffer with hardware telemetry from accel.js
    //      SharedArrayBuffer-backed peer state for zero-copy Worker handoff
    aguwa.initBuffer({ threads: accel.HW.threads, totalTops: accel.HW.totalTops });

    // 1b. Initialize time source detection (async — MA-902 SNMP init)
    await this._initTimeSource();

    // 1c. Seed AGUWA from GPS time (MA-902) so correctionMs is accurate from the start
    //     Without this, aguwa.now() = Date.now() + 0, and nodes on different machines
    //     will have >500ms divergence even when sharing the same GPS time server
    if (this.timeSource) {
      const status = this.timeSource.getStatus();
      if (status.ma902?.available && typeof status.ma902?.clockOffset === 'number') {
        // clockOffset is signed: GPS_time - system_time (seconds)
        // Positive = system behind hardware, negative = system ahead
        const offsetMs = status.ma902.clockOffset * 1000;
        if (Math.abs(offsetMs) >= 10 && Math.abs(offsetMs) < 60_000) {
          aguwa.calibrateFromHardware(Math.floor(Date.now() / 1000) + status.ma902.clockOffset);
        } else if (Math.abs(offsetMs) < 10) {
          log.debug('AGUWA: System clock within 10ms of hardware — no calibration needed');
        }
      }
    }

    // 1c. Register GPS jitter entropy source with PRAHARI (lazy — needs MANI)
    if (this.timeSource) {
      registerGPSJitterWithPrahari(prahari, this.timeSource);
    }

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
      // JHILKE: Pass oracle code hash for deterministic bootstrap key derivation
      codeHash: this.oracle?.selfHash,
      // JHILKE: Per-build nonce for bootstrap key + dialect strengthening
      buildNonce: this._buildNonce || null,
    });

    // Defensive: warn if buildNonce is missing — JHILKE bootstrap keys will
    // use empty string fallback, which STILL works (both sides derive from '')
    // but makes the key publicly derivable from source code alone.
    if (!this._buildNonce) {
      log.warn('⚠️  JHILKE: No buildNonce (data/manifest.json missing or has no buildNonce). Bootstrap keys are weakened.');
    } else {
      log.info(`🔑 JHILKE: buildNonce loaded (${this._buildNonce.slice(0, 12)}...)`);
    }

    await this.mesh.start();

    // 3a½. Wire JHILKE chirp events to KARMA for peer reputation
    if (this.mesh.jhilke) {
      this.mesh.jhilke.on('chirp:failed', ({ peerId, consecutiveFailures }) => {
        // After 3 consecutive failures, penalize via KARMA
        if (consecutiveFailures >= 3) {
          aguwa.updateKarma(peerId, -1);
          log.warn('JHILKE chirp failure → KARMA penalty', { peer: peerId.slice(0, 16), consecutiveFailures });
        }
      });
    }

    // 3a. Register mesh arrival entropy source with PRAHARI (lazy — needs mesh)
    registerMeshEntropyWithPrahari(prahari, this.mesh);

    // 3a². Wire PRAHARI ↔ AGUWA bidirectional link:
    //   AGUWA → PRAHARI: Kuramoto residuals as sponge entropy (weight 6)
    //   PRAHARI → AGUWA: Mesh jitter variance modulates coupling strength
    this._aguwaEntropyLink = wireAguwaWithPrahari(prahari);

    // 3. Initialize replication
    this.replication = new ReplicationEngine(this.mesh, this.config.database.path);
    await this.replication.init();

    // 3b. Ensure user_profiles table exists in replication DB
    ensureProfileTable(this.replication);

    if (this.config.database.replication.enabled) {
      this.replication.startSync(this.config.database.replication.syncInterval);
    }

    // 4. Start gossip protocol
    this.gossip = new GossipProtocol(this.mesh, this.identity, {
      fanout: 3,
      helloInterval: 30000,
      // Relay info callback — gossip includes our relay endpoints in HELLO broadcasts
      getRelayInfo: () => this._getActiveRelayInfo(),
      // Relay connect callback — gossip tells us to register with a discovered relay
      connectRelay: (endpoint, nodeId) => this._registerWithRelay({ relayEndpoint: endpoint, nodeId: nodeId || `relay-${aguwa.now()}` }),
    });
    this.gossip.start();

    // 4a. Wire PRAHARI Commit-Reveal entropy protocol into gossip
    //     Registers as 'mesh-commit-reveal' entropy source (weight: 10, highest)
    //     Subscribes to prahari:entropy:commit / prahari:entropy:reveal rumor topics
    //     MANI: Epoch-aligned rounds based on time trust level
    //     SAKSHI: Witness validation + behavioral velocity monitoring
    this.commitReveal = wireCommitReveal({
      gossip: this.gossip,
      prahari,
      mesh: this.mesh,
      nodeId: this.identity.identity.nodeId,
      maniDetector: this.timeSource || null,
      sakshiMonitor: this.velocityMonitor || null,
      witnessMap: this._getWitnessMap?.() || new Map(),
      signFn: (data) => this.identity.sign(data),
      publicKey: this.identity.identity.publicKey,
    });

    // 4b. Wire profile gossip — handles 'profile:update' rumors
    wireProfileGossip({
      mesh: this.mesh,
      replication: this.replication,
      identity: this.identity,
    });

    // 4b2. Initialize Server Directory (C2C Lighthouse)
    //      Collects 'server:heartbeat' rumors from C2C game servers.
    //      Optional beacon file writer for yakmesh.dev public server list.
    this.serverDirectory = new ServerDirectory({
      beaconPath: process.env.SERVER_BEACON === 'true'
        ? join(this.config.publicDir || 'public', 'servers.json')
        : null,
    });
    this.serverDirectory.start();
    log.info('✓ Server Directory (C2C Lighthouse) started');

    // 4c. Initialize TME encoder + wire gossip
    //     Creates the TemporalMeshEncoder and listens for tme:* rumor topics
    //     Passes MANI timeSource for GPS/atomic timestamps, and a getter for
    //     the meshTimeReference (populated later by _startTimeHeartbeat)
    const { router: tmeRouter, encoder: tmeEncoder } = createTmeAPI({
      gossip: this.gossip,
      identity: this.identity,
      timeSource: this.timeSource || null,
      getMeshTimeRef: () => this.meshTimeReference || null,
      writeLimiter: (_req, _res, next) => next(), // placeholder — real limiter on routes
      tmeTransportGetter: () => this.tmeTransport || null,
    });
    this.tmeEncoder = tmeEncoder;
    this.tmeRouter = tmeRouter;

    wireTmeGossip({
      mesh: this.mesh,
      encoder: this.tmeEncoder,
      nodeId: this.identity.identity.nodeId,
    });

    // 4d. Wire TME dedicated wire protocol (Step 25)
    //     Adds point-to-point TME_SLICE, TME_PROOF_REQUEST/RESPONSE,
    //     TME_RECONSTRUCT handlers for multi-path dispatch + on-demand recovery.
    //     Gossip remains the broadcast backbone; wire protocol adds targeted delivery.
    this.tmeTransport = wireTmeTransport({
      mesh: this.mesh,
      encoder: this.tmeEncoder,
      nodeId: this.identity.identity.nodeId,
      log,
    });

    // Handle incoming rumors (data from other nodes)
    this.mesh.on('rumor', (topic, data, origin) => {
      log.debug(`📨 Rumor [${topic}] from ${peerTag(origin)}`);

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

      // Handle time heartbeat gossip (MANI grandmaster time propagation)
      if (topic === 'time:heartbeat') {
        this._handleTimeHeartbeat(data, origin);
      }

      // Handle C2C server heartbeats (Lighthouse directory)
      if (topic === 'server:heartbeat') {
        this.serverDirectory?.handleHeartbeat(data, origin);
      }

      // ── ACT (AGUWA Coordinated Transition) gossip topics ──

      // Handle ACT proposal from an upgraded node
      if (topic === 'act:proposal') {
        this._handleACTProposal(data, origin);
      }

      // Handle ACT consent from a peer
      if (topic === 'act:consent') {
        this._handleACTConsent(data, origin);
      }

      // Handle ACT state broadcast from a peer (PREPARE/READY/SWITCH)
      if (topic === 'act:state') {
        this._handleACTStateGossip(data, origin);
      }
    });

    // 4b. Start periodic time heartbeat gossip broadcast
    this._startTimeHeartbeat();

    // 4c. Start AGUWA → GeoProof propagation delay feed
    this._startAguwaGeoFeed();

    // 4d. ACT: Wire JHILKE state machine events + trigger proposal on first peer
    this._initACT();

    // Annex messages handled directly in mesh._handleMessage() — no separate routing needed

    // 5. Initialize content store for public delivery
    this.contentStore = new ContentStore({
      dataDir: this.config.database?.contentPath || './data/content',
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
    await this._initYakTun();
    await this._initTernaryHarmonization();

    // 5i. Initialize SHERPA for decentralized peer discovery
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
        log.debug(`No relay path to ${peerTag(targetNodeId)}`);
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
    this._relayExpiryInterval = setInterval(() => {
      if (!this._relayClients || this._relayClients.size === 0) return;
      const now = aguwa.now();
      const RELAY_CLIENT_TTL = 5 * 60 * 1000; // 5 minutes
      for (const [clientNodeId, lastSeen] of this._relayClients) {
        if (now - lastSeen > RELAY_CLIENT_TTL) {
          this._relayClients.delete(clientNodeId);
          // Also clear any queued messages and cached keys for expired client
          if (this._relayOutbox) this._relayOutbox.delete(clientNodeId);
          if (this.mesh?._relayPeerKeys) this.mesh._relayPeerKeys.delete(clientNodeId);
          log.debug(`Relay client expired: ${peerTag(clientNodeId)}`);
        }
      }
    }, 60000); // Check every minute

    // 5k. Start scheduled ML workloads through ComputeScheduler
    this._startScheduledWorkloads();

    // 6. Start HTTP server
    await this._startHttpServer();

    // 6b. Attach KOMM WebSocket upgrade paths to HTTP server
    this._initKommWebSocket();

    // 7. Connect to bootstrap nodes (non-blocking — runs in background)
    this._connectToBootstrap();

    // 7b. Auto-register with relay peers from YAKMESH_RELAY_PEERS env var
    this._connectToRelayPeers();

    // 7. Initialize PeerQuanta integration (if enabled)
    if (this.config.peerquanta?.enabled) {
      await this._initAdapter();
    }

    // 8. Initialize Website Adapter (if website directory exists)
    if (this.config.website?.enabled !== false) {
      await this._initWebsiteAdapter();
    }

    // 8b. Initialize YakAI Adapter (compute bridge for yakai)
    if (process.env.YAKMESH_YAKAI_ENABLED !== 'false') {
      await this._initYakaiAdapter();
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
      if (a.nvGpu) accelParts.push(`GPU(${a.nvGpuName}, ${a.nvGpuTops}T)`);
      if (a.amdNpu) accelParts.push(`NPU(${a.amdNpuTops}T)`);
      if (a.totalTops > 0) accelParts.push(`∑${a.totalTops}TOPS`);
      if (a.nativePQ) accelParts.push(`PQ(${a.nativePQBackend})`);
      if (accelParts.length > 0) {
        log.info(`  ACCEL:      ⚡ ${accelParts.join(' + ')}`);
      } else {
        log.info(`  ACCEL:      ○ pure-JS (install liboqs-node / onnxruntime-node for acceleration)`);
      }
      // Scheduler status
      const sched = accel.scheduler.getStatus();
      if (sched.initialized) {
        const devNames = Object.keys(sched.devices).map(d => d.toUpperCase()).join('+');
        const totalSlots = Object.values(sched.devices).reduce((s, d) => s + d.queue.capacity, 0);
        log.info(`  SCHEDULER:  ✓ ${devNames} heterogeneous (${totalSlots} queue slots, ${sched.routing.mode} routing)`);
      }
    }
    if (this.adapter) {
      log.info(`  Adapter:    ✓ Enabled`);
    }
    if (this.websiteAdapter && this.websiteAdapter.manifests.size > 0) {
      log.info(`  Website:    ✓ ${this.websiteAdapter.manifests.size} site(s) at /site/`);
    }
    log.info('');

    // 9a. Upgrade pipe server with anti-cheat ops (identity/karma/oracle now available)
    if (isPipeServerRunning()) {
      upgradePipeAntiCheat({
        identity: this.identity,
        karmaLimiter: getKarmaRateLimiter(),
        oracle: this.oracle,
        gossip: this.gossip,
        serverDirectory: this.serverDirectory,
      });
    }

    // 10. Start Time API (HTTP bridge to MA-902 GPS time server)
    try {
      await startTimeApi();
      log.info('  TIME API:   ✓ GPS telemetry at http://localhost:3099/api/time');
    } catch (err) {
      log.warn(`  TIME API:   ⚠️  Failed to start: ${err.message}`);
    }

    // 11. Start Caddy reverse proxy (HTTPS/443 with auto Let's Encrypt)
    // Only starts if YAKMESH_DOMAIN env var is set
    if (this.config.caddy?.enabled && this.config.caddy?.domain) {
      try {
        this.webServer = new YakmeshWebServer({
          domain: this.config.caddy.domain,
          autoHttps: this.config.caddy.autoHttps !== false,
          acmeEmail: this.config.caddy.acmeEmail,
          nodeProxy: true,
          nodeHttpPort: this.boundHttpPort || this.config.network.httpPort,
          nodeWsPort: this.mesh.boundPort || this.config.network.wsPort,
          root: './htdocs',
          logPath: './logs',
        });
        await this.webServer.start();
        log.info(`  CADDY:      ✓ HTTPS reverse proxy at https://${this.config.caddy.domain}`);
        log.info(`              → HTTP:${this.boundHttpPort || this.config.network.httpPort} WS:${this.mesh.boundPort || this.config.network.wsPort}`);
      } catch (err) {
        log.warn(`  CADDY:      ⚠️  Failed to start: ${err.message}`);
      }
    }

    return this;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // ACT — AGUWA Coordinated Transition
  //
  // Coordinates code upgrades across the mesh using AGUWA epoch boundaries,
  // JHILKE PREPARE/READY/SWITCH state machine, and MANTRA gossip propagation.
  // Triggered internally when manifest hash ≠ oracle selfHash on startup.
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Initialize ACT subsystem. Called once after gossip is ready.
   * Wires JHILKE state events to gossip propagation and listens for
   * first peer connection to trigger proposal if upgrade detected.
   */
  _initACT() {
    // Wire JHILKE ACT state events → gossip broadcast
    if (this.mesh?.jhilke) {
      this.mesh.jhilke.on('act:state', (stateData) => {
        if (this.gossip) {
          this.gossip.spreadRumor('act:state', {
            ...stateData,
            nodeId: this.identity.identity.nodeId,
          });
        }
      });

      // Wire JHILKE act:execute → graceful restart
      this.mesh.jhilke.on('act:execute', (data) => {
        this._executeACT(data);
      });
    }

    // If upgrade detected (Phase A), wait for first peer then propose
    if (this._actUpgradeDetected) {
      const onFirstPeer = () => {
        this.mesh.removeListener('peer:connected', onFirstPeer);
        // Delay slightly to let gossip stabilize
        setTimeout(() => this._initiateACTProposal(), 5000);
      };

      // Check if we already have peers
      if (this.mesh?.peers?.size > 0) {
        setTimeout(() => this._initiateACTProposal(), 5000);
      } else {
        this.mesh.on('peer:connected', onFirstPeer);
      }
    }
  }

  /**
   * Initiate ACT proposal (this node is the proposer — it detected the upgrade).
   * Computes target epoch from AGUWA propagation model and gossips proposal.
   */
  _initiateACTProposal() {
    if (!this.genesisNetwork || !this.gossip) return;
    if (this._actProposed) return; // Already proposed
    this._actProposed = true;

    // Compute target epoch from AGUWA propagation model (Phase F)
    const epochBuffer = aguwa.getACTEpochBuffer();
    const targetEpoch = getCurrentEpoch() + epochBuffer;

    // Create proposal via GenesisNetworkV2
    const proposal = this.genesisNetwork.proposeACT(targetEpoch);

    // Gossip the proposal
    this.gossip.spreadRumor('act:proposal', proposal);

    log.info('ACT: Proposal gossipped to mesh', {
      targetEpoch,
      epochBuffer,
      currentEpoch: getCurrentEpoch(),
    });

    // Auto-consent if env var set (for headless/unattended nodes)
    if (process.env.YAKMESH_ACT_AUTO_CONSENT === 'true') {
      this._consentACT(targetEpoch, 'accept');
    }
  }

  /**
   * Handle incoming ACT proposal from another node.
   * @param {Object} data - Proposal payload from act:proposal gossip
   * @param {string} origin - Proposer's nodeId
   */
  _handleACTProposal(data, origin) {
    if (origin === this.identity.identity.nodeId) return; // Ignore own proposals

    log.info('ACT: Proposal received from peer', {
      proposer: peerTag(origin),
      targetEpoch: data.targetEpoch,
      proposerNetwork: data.proposerName,
    });

    this._pendingACTProposal = data;

    // Auto-consent if env var set (headless nodes)
    if (process.env.YAKMESH_ACT_AUTO_CONSENT === 'true') {
      this._consentACT(data.targetEpoch, 'accept');
    }
    // Otherwise, the operator UI or API should call _consentACT()
  }

  /**
   * Consent to an ACT proposal.
   * @param {number} targetEpoch
   * @param {'accept'|'abstain'|'reject'} vote - JHILKE ternary vote
   */
  _consentACT(targetEpoch, vote) {
    if (this._actConsented) return;
    this._actConsented = true;

    const consent = {
      vote,
      targetEpoch,
      nodeId: this.identity.identity.nodeId,
      fingerprint: this.genesisNetwork?.fingerprint,
    };

    // Gossip consent
    this.gossip.spreadRumor('act:consent', consent);

    log.info('ACT: Consent sent', { vote, targetEpoch });

    // If accepted, start JHILKE state machine
    if (vote === 'accept' && this.mesh?.jhilke) {
      const epochBuffer = aguwa.getACTEpochBuffer();
      this.mesh.jhilke.beginACT(targetEpoch, epochBuffer);
    }
  }

  /**
   * Handle ACT consent from a peer.
   * @param {Object} data - Consent payload
   * @param {string} origin - Peer's nodeId
   */
  _handleACTConsent(data, origin) {
    if (origin === this.identity.identity.nodeId) return;

    // Register consent in GenesisNetworkV2
    this.genesisNetwork?.handleACTConsent(origin, data);

    log.info('ACT: Peer consent received', {
      peer: peerTag(origin),
      vote: data.vote,
      targetEpoch: data.targetEpoch,
    });
  }

  /**
   * Handle ACT state gossip from a peer (PREPARE/READY/SWITCH).
   * Forwards to JHILKE state machine for coordination.
   * @param {Object} data - { state, targetEpoch, nodeId }
   * @param {string} origin - Peer's nodeId
   */
  _handleACTStateGossip(data, origin) {
    if (origin === this.identity.identity.nodeId) return;

    // Forward to JHILKE state machine
    this.mesh?.jhilke?.handleACTState(origin, data);
  }

  /**
   * Execute ACT — graceful coordinated restart.
   * Called by JHILKE state machine when SWITCH terminal state is reached
   * at the target epoch boundary with sufficient AGUWA orderParameter.
   *
   * Sequence: stop JHILKE → close ANNEX → flush PRAHARI → close WS →
   *           write act-restart.json → process.exit(0)
   *
   * NO special WS close codes. Standard 1000/1001 only.
   * Peers reconnect via existing logic and re-verify via GenesisNetworkV2.
   * @param {Object} data - { targetEpoch }
   */
  async _executeACT(data) {
    log.warn('ACT: ═══ EXECUTING COORDINATED TRANSITION ═══', {
      targetEpoch: data.targetEpoch,
      currentEpoch: getCurrentEpoch(),
      orderParameter: aguwa.orderParameter().toFixed(3),
    });

    // Write act-restart marker so the next startup knows this was an ACT restart
    const restartMarker = {
      actVersion: 1,
      targetEpoch: data.targetEpoch,
      executedAt: new Date().toISOString(),
      previousHash: this._actManifestHash || null,
      newHash: this.oracle?.selfHash || null,
    };

    const markerPath = join(import.meta.dirname, '..', 'data', 'act-restart.json');
    writeFileSync(markerPath, JSON.stringify(restartMarker, null, 2));
    log.info('ACT: Restart marker written to data/act-restart.json');

    // Graceful shutdown sequence
    await this.stop();

    log.info('ACT: ═══ TRANSITION COMPLETE — exiting for restart ═══');
    process.exit(0);
  }

  async stop() {
    log.info('\n🛑 Stopping Yakmesh Node...');

    this.adapter?.stopSync();
    this.timeSource?.stop();  // Stop time source monitoring
    await stopTimeApi().catch(() => { });  // Stop time API server
    this.consensus?.stop();  // Stop consensus engine
    this.yurtHub?.stop();  // Stop YURT room gossip
    this.velocityMonitor?.stop?.();  // Stop velocity monitoring
    this.karmaModel?.stopPromotionChecks?.();  // Stop KARMA auto-promotion
    this.nakpakRouter?.cleanupCircuits?.();  // Cleanup NAKPAK circuits
    this.kommWss?.close();  // Close KOMM WebSocket server
    this.serverDirectory?.stop();  // Stop C2C Lighthouse directory
    // Stop Caddy web server
    if (this.webServer) {
      await this.webServer.stop().catch(() => { });
    }
    // Stop scheduled workloads
    if (this._entropyCheckTimer) clearInterval(this._entropyCheckTimer);
    if (this._peerAssessTimer) clearInterval(this._peerAssessTimer);
    if (this._timeHeartbeatInterval) clearInterval(this._timeHeartbeatInterval);
    if (this._messageCountInterval) clearInterval(this._messageCountInterval);
    if (this._relayExpiryInterval) clearInterval(this._relayExpiryInterval);
    await accel.scheduler.shutdown();  // Drain compute scheduler queues
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

    // iO Manifest verification — compare deployed file list against current disk state
    this._verifyDeployManifest();

    // Initialize iO-inspired network identity (hash obfuscation)
    this._initGenesisNetwork();
  }

  /**
   * Verify the iO deployment manifest (data/manifest.json) if present.
   * Graceful degradation: no manifest → skip silently.
   * Stale files are handled per YAKMESH_AUTO_PRUNE / YAKMESH_QUARANTINE env vars.
   */
  _verifyDeployManifest() {
    const manifestPath = join(import.meta.dirname, '..', 'data', 'manifest.json');
    let manifest = null;
    try {
      if (existsSync(manifestPath)) {
        manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
        log.info(`📋 iO Manifest: loaded (${manifest.fileCount} files, hash=${manifest.codebaseHash})`);
        // Store buildNonce for JHILKE bootstrap key strengthening
        if (manifest.buildNonce) {
          this._buildNonce = manifest.buildNonce;
        }
        // ACT Phase A: Detect code upgrade by comparing manifest hash to live oracle hash.
        // manifest.fullCodebaseHash = hash at build time; oracle.selfHash = hash of code on disk now.
        // If they differ, code was updated since the last build → initiate ACT proposal after mesh connects.
        if (manifest.fullCodebaseHash && this.oracle?.selfHash) {
          if (manifest.fullCodebaseHash !== this.oracle.selfHash) {
            this._actUpgradeDetected = true;
            this._actManifestHash = manifest.fullCodebaseHash;
            log.warn('📋 ACT: Code upgrade detected — manifest hash differs from oracle selfHash');
          }
        }
      }
    } catch (err) {
      log.warn(`📋 iO Manifest: failed to load — ${err.message}`);
    }

    const result = this.oracle.verifyManifest(manifest);

    if (result.skipped) {
      log.info('📋 iO Manifest: not present — running in legacy mode (hash everything found)');
      return;
    }

    if (result.valid) {
      log.info(`📋 iO Manifest: ✓ verified (${result.fileCount} files)`);
    } else {
      log.warn(`📋 iO Manifest: ${result.missing.length} missing files detected`);
    }

    if (result.unexpected.length > 0) {
      log.info(`📋 iO Manifest: ${result.unexpected.length} files not in manifest`);
      // Handle stale files (rename/delete/quarantine based on env vars)
      const staleResult = this.oracle.handleStaleFiles(result.unexpected);
      if (staleResult.handled > 0) {
        log.info(`📋 iO Stale files: ${staleResult.handled} handled (mode=${staleResult.mode})`);
        // Re-verify after pruning to get clean oracle hash
        if (staleResult.mode !== 'none') {
          log.info('📋 iO Manifest: re-computing oracle hash after stale file handling...');
        }
      }
    }
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
  async _initTimeSource() {
    log.info('⏰ Initializing Time Source Detection...');

    // Get or create global time source detector
    // MA-902/S-C1 GPS Time Server on LAN — provides satellite telemetry via SNMP
    this.timeSource = getTimeSourceDetector({
      detectHardware: true,
      checkNtp: true,
      refreshInterval: 60000,  // Re-check every minute
      verbose: false,
      ma902: this.config.mani?.ma902 || {
        host: '192.168.1.30',   // MA-902/S-C1 Gigabit PTP Time Server
        pollInterval: 10000,     // Poll SNMP telemetry every 10s
        enabled: process.env.MA902_ENABLED === 'true' // Disable by default for non-LAN users
      },
    });

    // Perform initial detection
    const results = this.timeSource.detect();

    // Configure phase epochs based on detected time source
    if (results.trustLevel) {
      setTimeSourceConfig(results.trustLevel);
    }

    // Start continuous monitoring (async — initialises MA-902 SNMP session)
    await this.timeSource.start();

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

    // Track last known trust level to only log on actual changes
    let lastKnownTrustLevel = results.trustLevel;

    // Listen for trust level changes
    this.timeSource.on('detected', (newResults) => {
      if (newResults.trustLevel !== lastKnownTrustLevel) {
        log.info(`⏰ Time source changed: ${lastKnownTrustLevel.toUpperCase()} → ${newResults.trustLevel.toUpperCase()}`);
        lastKnownTrustLevel = newResults.trustLevel;
        setTimeSourceConfig(newResults.trustLevel);
      }
    });

    log.info('✓ Time Source initialized');
  }

  // =========================================
  // MANI Time Heartbeat Gossip
  // =========================================
  // Broadcasts local time source status via MANTRA gossip so that every
  // mesh peer receives grandmaster-quality timing data even if it only
  // has system-clock NTP.  On the LAN node this carries MA-902 GPS
  // satellite telemetry; on Hostinger (or any peer) the incoming
  // heartbeats populate `this.meshTimeReference` — the best-known
  // atomic/GPS time from the mesh.
  //
  // Public NTP: time.yakmesh.dev (UDP 123 → MA-902 GPS grandmaster)
  // =========================================

  /**
   * Start periodic time heartbeat gossip.
   * Called once after gossip + timeSource are both initialized.
   */
  _startTimeHeartbeat() {
    // Mesh time reference — best peer time we've received via gossip
    this.meshTimeReference = null;

    const HEARTBEAT_INTERVAL = 30_000; // 30 s (matches relay poll cadence)

    const broadcast = () => {
      if (!this.gossip || !this.timeSource) return;

      const status = this.timeSource.getStatus();
      const sats = status.ma902?.satellites || status.satellites || {};
      const locked = status.trustLevel === 'gps' || status.trustLevel === 'atomic';

      const heartbeat = {
        // Node identity
        nodeId: this.identity.identity.nodeId,
        nodeName: this.identity.identity.name,
        // Time quality
        trustLevel: status.trustLevel,
        stratum: status.stratum ?? (locked ? 1 : 2),
        accuracy_ms: locked ? 1 : 50,
        phaseTolerance: status.phaseTolerance,
        primarySource: status.primarySource,
        // Satellite telemetry (only meaningful on GPS-backed nodes)
        satellites: {
          visible: sats.visible ?? 0,
          used: sats.used ?? 0,
          tracking: sats.tracking ?? 0,
          constellations: sats.constellations ?? [],
        },
        lock: locked,
        quality: locked ? 'excellent' : 'degraded',
        offset_ns: status.offset ?? 0,
        reference_id: locked ? 'GPS' : 'SYS',
        // MA-902 enrichment (when available)
        ma902: status.ma902 ? {
          host: status.ma902.host,
          locked: status.ma902.locked,
          gpsTime: status.ma902.gpsTimeISO,
          clockDelta: status.ma902.clockDeltaSeconds,
          alarm: status.ma902.alarm,
          quality: status.ma902.qualityIndicator,
        } : null,
        // Public NTP endpoint (resolvable from anywhere on the internet)
        publicNtp: locked ? 'time.yakmesh.dev' : null,
        // Timestamp of this heartbeat (local clock)
        timestamp: aguwa.now(),
      };

      this.gossip.spreadRumor('time:heartbeat', heartbeat);
    };

    // First heartbeat after a short delay (let relay connect)
    setTimeout(broadcast, 5_000);
    // Then every 30 s
    this._timeHeartbeatInterval = setInterval(broadcast, HEARTBEAT_INTERVAL);

    log.info('⏰ MANI time heartbeat gossip started (every 30 s)');
  }

  /**
   * Handle an incoming time:heartbeat rumor from a peer.
   * Keeps track of the best (lowest stratum) grandmaster in the mesh.
   */
  _handleTimeHeartbeat(data, origin) {
    // Ignore our own heartbeats
    if (origin === this.identity.identity.nodeId) return;

    // AGUWA Kuramoto coupling: feed heartbeat arrival time so phase correction converges
    // This is the critical wiring that makes aguwa.now() converge across peers
    aguwa.onHeartbeat(origin, aguwa.now());

    // Update peer's MANI trust in AGUWA so coupling strength is calculated correctly
    const aguwaPeer = aguwa.peers.get(origin);
    if (aguwaPeer && data.trustLevel) {
      aguwaPeer.capabilities = { ...aguwaPeer.capabilities, maniTrust: data.trustLevel };
    }

    const peerStratum = data.stratum ?? 16;
    const peerLocked = !!data.lock;
    const currentBest = this.meshTimeReference;

    // Accept if:  no current reference, OR this peer has a lower (better) stratum,
    //             OR same stratum but this one is locked and current isn't
    const dominated =
      !currentBest ||
      peerStratum < (currentBest.stratum ?? 16) ||
      (peerStratum === (currentBest.stratum ?? 16) && peerLocked && !currentBest.lock);

    if (dominated) {
      this.meshTimeReference = {
        ...data,
        receivedAt: aguwa.now(),
        fromNodeId: origin,
      };

      log.info(`⏰ Mesh time reference updated — ${data.nodeName || peerTag(origin)} ` +
        `stratum ${peerStratum}, lock=${peerLocked}, ` +
        `sats=${data.satellites?.used ?? 0}/${data.satellites?.visible ?? 0}` +
        (data.publicNtp ? `, ntp=${data.publicNtp}` : ''));
    } else if (currentBest && origin === currentBest.fromNodeId) {
      // Same grandmaster, refresh its data
      this.meshTimeReference = {
        ...data,
        receivedAt: aguwa.now(),
        fromNodeId: origin,
      };
    }

    // AGUWA → GeoProof: auto-register GPS/Atomic peers as landmarks
    // Locked peers have stratum-1 timing — ideal distance-bound anchors
    if (peerLocked) {
      this._ensureGeoProofService();
      if (this.geoProofService) {
        const lm = this.geoProofService.landmarkRegistry.get(origin);
        if (!lm) {
          this.geoProofService.registerLandmark({
            nodeId: origin,
            name: data.nodeName || `GPS-${peerTag(origin)}`,
            timeSource: data.trustLevel || 'gps',
          });
          log.debug(`📍 Auto-registered GPS peer as geo-proof landmark`, { peer: peerTag(origin) });
        }
      }
    }
  }

  /**
   * Lazily initialize GeoProofService if it hasn't been created yet.
   * Requires timeSource and identity to be available.
   */
  _ensureGeoProofService() {
    if (this.geoProofService) return;
    if (!this.timeSource || !this.identity) return;
    this.geoProofService = new GeoProofService({
      nodeId: this.identity.identity.nodeId,
      timeSourceDetector: this.timeSource,
    });
  }

  /**
   * Start periodic AGUWA → GeoProof measurement feed.
   * Every 60 s, reads propagation delays from AGUWA and feeds them
   * into GeoProofService as RTT-equivalent measurements.
   */
  _startAguwaGeoFeed() {
    const FEED_INTERVAL = 60_000; // 60 s

    this._aguwaGeoFeedInterval = setInterval(() => {
      if (!this.geoProofService) return;
      const delays = aguwa.getPropagationDelays();
      if (delays.size === 0) return;
      this.geoProofService.addAGUWAMeasurements(delays);
    }, FEED_INTERVAL);

    log.info('📍 AGUWA → GeoProof measurement feed started (every 60 s)');
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
      inferenceEngine: accel.inference,
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
      this._messageCountWindow = new Map(); // peerId -> count in current window

      this.mesh.on('rumor', (topic, data, origin) => {
        const rumor = { origin };
        if (!rumor.origin) return;
        const count = (this._messageCountWindow.get(rumor.origin) || 0) + 1;
        this._messageCountWindow.set(rumor.origin, count);
        this.velocityMonitor.observe(
          rumor.origin,
          BEHAVIOR_DIMENSION.MESSAGE_RATE,
          count
        );
      });

      // Reset message count window every minute
      this._messageCountInterval = setInterval(() => { this._messageCountWindow.clear(); }, 60000);
    }

    log.info('✓ SAKSHI initialized (witness consensus + velocity monitoring)');
  }

  /**
   * Get current witness map (nodeId → NodeWitness) for CommitReveal quality weighting.
   * Built from known peers + our own SAKSHI witness profile.
   */
  _getWitnessMap() {
    const map = new Map();
    // Add our own witness
    if (this.sakshiWitness) {
      map.set(this.identity.identity.nodeId, this.sakshiWitness);
    }
    // Add known peer witnesses from velocity monitor profiles
    if (this.velocityMonitor?.profiles) {
      for (const [nodeId] of this.velocityMonitor.profiles) {
        if (!map.has(nodeId)) {
          // Create a basic witness for known peers based on observed behavior
          try {
            map.set(nodeId, new NodeWitness({ nodeId }));
          } catch { /* ignore — peer may not have full profile yet */ }
        }
      }
    }
    return map;
  }

  /**
   * Initialize YAK-TUN: The OS-to-Mesh native bridge
   */
  async _initYakTun() {
    log.info('🌐 Initializing YAK-TUN Native Interface...');
    this.yakTun = new YakTun('yak0', this.mesh, this.karmaModel);
    await this.yakTun.init();

    // Route incoming TUN_PACKET messages from the mesh directly back into OS
    this.mesh.messageHandlers.get('TUN_PACKET')?.push?.((msg, ws, senderNodeId) => {
      if (this.yakTun && this.yakTun.active) {
        this.yakTun.onReceive(msg, senderNodeId);
      }
    }) || this.mesh.messageHandlers.set('TUN_PACKET', [(msg, ws, senderNodeId) => {
      if (this.yakTun && this.yakTun.active) {
        this.yakTun.onReceive(msg, senderNodeId);
      }
    }]);
  }

  /**
   * Initialize KARMA trust model
   * SAKSHI velocity alerts feed into KARMA trust assessments.
   */
  _initKarma() {
    log.info('☯️ Initializing KARMA...');

    this.karmaModel = new KarmaTrustModel({
      ...this.config.karma,
      inferenceEngine: accel.inference,
    });

    // Restore persisted KARMA state from disk (non-blocking, non-fatal)
    const karmaPath = `${this.config?.node?.dataDir || './data'}/karma-store.json`;
    this.karmaModel.loadFromDisk(karmaPath).then(ok => {
      if (ok) log.info(`☯️ KARMA restored from ${karmaPath} (${this.karmaModel.evidence.size} nodes)`);
    }).catch(() => { });

    // Auto-save KARMA on trust level changes (debounced to max once/30s inside saveToDisk)
    const saveKarma = () => {
      this.karmaModel.saveToDisk(karmaPath).catch(err => {
        log.debug('KARMA save failed (non-fatal)', { err: err.message });
      });
    };
    this.karmaModel.on('promoted', saveKarma);
    this.karmaModel.on('demoted', saveKarma);

    // Wire SAKSHI velocity alerts → KARMA trust adjustments (ternary: NEGATIVE/NEUTRAL/ignored)
    if (this.velocityMonitor) {
      this.velocityMonitor.onAlert((alert) => {
        const { nodeId, level, dimension, zScore } = alert;

        // ═══ TRIBHUJ ternary mapping ═══
        // CRITICAL → NEGATIVE karma (record as failed verification)
        // WARNING  → NEUTRAL observation (beacon sighting — keeps node active)
        // ELEVATED → ignored (normal variance — no karmic consequence)
        if (level === VELOCITY_ALERT.CRITICAL) {
          log.warn(`☯️ KARMA: Critical velocity alert for ${peerTag(nodeId)} (${dimension}, z=${zScore.toFixed(1)}) → NEGATIVE`);
          // Record negative evidence — failed behavioral verification
          this.karmaModel.recordDokoVerification(nodeId, {
            passed: false,
            reason: `Critical velocity anomaly: ${dimension} (z-score ${zScore.toFixed(1)})`,
          });

          // Schedule deep NPU anomaly assessment via ComputeScheduler (HIGH)
          const karmaEvidence = this.karmaModel.getEvidence(nodeId);
          this._scheduledAnomalyAssessment(nodeId, {
            karmaScore: karmaEvidence?.trustScore ? karmaEvidence.trustScore / 100 : 0.5,
          }).then(({ result }) => {
            if (result?.anomalyScore > 0.7) {
              log.warn(`👁️ SAKSHI: Deep assessment confirms anomaly for ${peerTag(nodeId)} (score=${result.anomalyScore.toFixed(3)})`);
            }
          }).catch(() => { }); // Non-fatal — scheduler may reject under load

        } else if (level === VELOCITY_ALERT.WARNING) {
          log.debug(`☯️ KARMA: Warning velocity alert for ${peerTag(nodeId)} (${dimension}) → NEUTRAL`);
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

    // Wire KARMA trust level changes → scheduled NPU trust prediction (second opinion)
    this.karmaModel.on('promoted', ({ nodeId, from, to, reason }) => {
      const nid = String(nodeId ?? 'unknown');
      log.info(`☯️ KARMA: Node ${peerTag(nid)} promoted ${from}→${to} (${reason})`);
      // Schedule NPU trust prediction for the promoted node
      const evidence = this.karmaModel.getEvidence(nid);
      if (evidence) {
        this._scheduledTrustPrediction(evidence).then(({ result }) => {
          if (result?.predicted) {
            const agrees = result.predicted === ['UNTRUSTED', 'SEEKING', 'AWAKENED', 'ENLIGHTENED'][to];
            log.debug(`☯️ KARMA NPU: ${result.source} predicts ${result.predicted} (${agrees ? 'agrees' : 'disagrees'} with rule-based ${to})`);
          }
        }).catch(() => { }); // Non-fatal
      }
    });

    this.karmaModel.on('demoted', ({ nodeId, from, to, reason }) => {
      const nid = String(nodeId ?? 'unknown');
      log.warn(`☯️ KARMA: Node ${peerTag(nid)} demoted ${from}→${to} (${reason})`);
      // Schedule NPU trust prediction for the demoted node
      const evidence = this.karmaModel.getEvidence(nid);
      if (evidence) {
        this._scheduledTrustPrediction(evidence).then(({ result }) => {
          if (result?.predicted) {
            const agrees = result.predicted === ['UNTRUSTED', 'SEEKING', 'AWAKENED', 'ENLIGHTENED'][to];
            log.debug(`☯️ KARMA NPU: ${result.source} predicts ${result.predicted} (${agrees ? 'agrees' : 'disagrees'} with rule-based ${to})`);
          }
        }).catch(() => { }); // Non-fatal
      }
    });

    log.info('✓ KARMA trust model initialized (SAKSHI → trust assessment pipeline)');

    // Wire KARMA model to mesh for admission decisions
    if (this.mesh) this.mesh.setKarmaModel(this.karmaModel);
  }

  // =========================================================================
  // TERNARY HARMONIZATION — SST × YPC-27 × 162T × ML unification
  // =========================================================================

  /**
   * Initialize the ternary harmonization stack.
   * Wires together SST-rotated YPC-27 checksums, batch verification,
   * ternary ML inference, and 162T hierarchical addressing.
   * 
   * Call after _initKarma() since it depends on the trust model.
   */
  async _initTernaryHarmonization() {
    log.info('◬ Initializing ternary harmonization stack...');

    // ── 1. 162T Address — derive from node identity ──
    const nodeId = this.identity?.publicKeyHex || crypto.randomBytes(32).toString('hex');
    this.tritAddress = hexIdToAddress(nodeId, {
      summit: 0,  // Summit 0 = default mesh
    });
    log.info(`◬ 162T address: ${this.tritAddress.toString()}`);

    // ── 2. Ternary routing table ──
    this.ternaryRouter = new TernaryRoutingTable(this.tritAddress, 6);

    // Wire mesh peer connections → ternary routing table
    this.mesh.on('peer:connected', (peerId) => {
      try {
        const peerAddress = hexIdToAddress(peerId);
        this.ternaryRouter.addPeer(peerId, peerAddress);
        log.debug(`◬ 162T: Added peer ${peerTag(peerId)} (tier distance: ${this.tritAddress.tierDistance(peerAddress)})`);
      } catch (err) {
        log.debug(`◬ 162T: Could not add peer address: ${err.message}`);
      }
    });

    this.mesh.on('peer:disconnected', (peerId) => {
      this.ternaryRouter.removePeer(peerId);
    });

    // Wire mesh peer connections → ComputeScheduler mesh awareness
    this.mesh.on('peer:connected', (peerId) => {
      const peer = this.mesh.peers?.get(peerId);
      if (peer?.capabilities) {
        accel.scheduler.addMeshPeer(peerId, peer.capabilities);
      }
    });
    this.mesh.on('peer:disconnected', (peerId) => {
      accel.scheduler.removeMeshPeer(peerId);
    });

    // ── 3. Ternary inference adapter (bridges TRIBHUJ → ONNX) ──
    this.ternaryInference = new TernaryInferenceAdapter(accel.inference);

    // Wire KARMA trust changes → ternary trust classification (second opinion)
    if (this.karmaModel) {
      this.karmaModel.on('promoted', ({ nodeId, to }) => {
        const evidence = this.karmaModel.getEvidence(nodeId);
        if (evidence) {
          this._scheduledTernaryTrustClassification(nodeId, evidence.trustScore || 50)
            .catch(() => { }); // Non-fatal
        }
      });

      this.karmaModel.on('demoted', ({ nodeId, to }) => {
        const evidence = this.karmaModel.getEvidence(nodeId);
        if (evidence) {
          this._scheduledTernaryTrustClassification(nodeId, evidence.trustScore || 50)
            .catch(() => { }); // Non-fatal
        }
      });
    }

    // ── 4. Batch checksum verifier — start auto-flush ──
    // The BatchChecksumVerifier uses ComputeScheduler internally
    log.info(`◬ Batch checksum verifier ready (flush threshold: ${batchChecksumVerifier.batchSize})`);

    log.info('✓ Ternary harmonization stack initialized (YPC27_SST + BatchVerify + TernaryML + 162T)');

    // ═══════════════════════════════════════════════════════════════════════
    // SANGHA — Unified Component Attestation (collective security)
    // ═══════════════════════════════════════════════════════════════════════
    // SANGHA creates cryptographic synapses between components for mutual
    // attestation. Unlike isolation (each stands alone), SANGHA components
    // protect each other — no component can be compromised silently.
    // ═══════════════════════════════════════════════════════════════════════
    log.info('🔗 Initializing SANGHA (collective attestation)...');

    const sangha = getSangha();

    // Bind time source for temporal attestations
    if (this.timeSource) {
      sangha.bindTimeSource(this.timeSource);
    }

    // Register core components with the collective
    // Each component provides a state getter for antibody circulation
    joinSangha(SANGHA_COMPONENT.CRYPTO, accel, () => ({
      initialized: accel.initialized,
      nativeSha3: accel.HW.nativeSha3,
      gpuAvailable: accel.HW.gpuAvailable,
      npuAvailable: accel.HW.npuAvailable,
    }));

    joinSangha(SANGHA_COMPONENT.ORACLE, this.oracle, () => ({
      network: this.oracle?.getNetworkId?.() || 'unknown',
      epoch: this.consensus?.getCurrentEpoch?.() || 0,
      timeSource: this.timeSource?.getSourceType?.() || 'unknown',
    }));

    joinSangha(SANGHA_COMPONENT.MESH, this.mesh, () => ({
      peerId: this.identity?.peerId || 'unknown',
      peerCount: this.mesh?.getPeerCount?.() || 0,
      annexActive: this.mesh?.annex?.enabled || false,
    }));

    joinSangha(SANGHA_COMPONENT.HTTP, this.app, () => ({
      port: this.boundHttpPort || this.config.httpPort,
      routes: this.app?._router?.stack?.length || 0,
    }));

    joinSangha(SANGHA_COMPONENT.IDENTITY, this.identity, () => ({
      peerId: this.identity?.peerId || 'unknown',
      keyAlgorithm: 'ML-DSA-65',
      hasPrivateKey: !!this.identity?.privateKey,
    }));

    // Start the collective (antibody circulation every 5s)
    sangha.start({ circulationIntervalMs: 5000 });

    // Subscribe to collective events
    sangha.on('anomalyDetected', (anomalies) => {
      log.error('🚨 SANGHA: Anomalies detected in component collective', {
        count: anomalies.length,
        types: anomalies.map(a => a.type),
      });
    });

    sangha.on('collectiveResponse', (response) => {
      log.warn('🛡️ SANGHA: Collective response triggered', response);
    });

    this.sangha = sangha;
    log.info('✓ SANGHA initialized (collective attestation active)');

    // ═══════════════════════════════════════════════════════════════════════
    // FS HARDENING — File Integrity with SANGHA-FS Integration
    // ═══════════════════════════════════════════════════════════════════════
    // File guardians protect critical files and join the SANGHA collective.
    // Tampering triggers collective response — no silent compromise possible.
    // ═══════════════════════════════════════════════════════════════════════
    log.info('[FS] Initializing FS Hardening (file guardians)...');

    const fsHardening = getFSHardening(this.dataDir);
    await fsHardening.init();

    // Bind to SANGHA for collective response
    fsHardening.bindSangha(sangha);

    // Register FS as a SANGHA component
    joinSangha('fs', fsHardening, async () => {
      const status = fsHardening.getStatus();
      return {
        guardianCount: status.files.length,
        allLocked: status.files.every(f => f.locked),
        sanghaConnected: status.sanghaConnected,
      };
    });

    // Forward tamper events to SANGHA
    fsHardening.on('tamper', (event) => {
      log.error('[!] FS TAMPER DETECTED - alerting SANGHA', event);
      // The collective will respond via anomalyDetected event
    });

    // Start periodic verification (30s interval)
    fsHardening.start(30000);

    this.fsHardening = fsHardening;
    log.info('✓ FS Hardening initialized', { guardians: fsHardening.getStatus().files.length });

    // ═══════════════════════════════════════════════════════════════════════
    // MEMORY SAFETY — Circulating Canaries
    // ═══════════════════════════════════════════════════════════════════════
    // Canaries are strategically-placed memory regions with known content.
    // During SANGHA circulation, canaries are checksummed and attested.
    // Corruption (buffer overflow, use-after-free) is detected in one cycle.
    // ═══════════════════════════════════════════════════════════════════════
    log.info('[MEM] Initializing Memory Safety (circulating canaries)...');

    const memorySafety = getMemorySafety();
    memorySafety.init();

    // Bind to SANGHA for collective response
    memorySafety.bindSangha(sangha);

    // Register as SANGHA component
    joinSangha('memory', memorySafety, async () => {
      return memorySafety.getState();
    });

    // Forward corruption events
    memorySafety.on('corruption', (corruptions) => {
      log.error('[!] MEMORY CORRUPTION - alerting SANGHA', { count: corruptions.length });
    });

    // Start monitoring (sync with SANGHA circulation)
    memorySafety.start(5000);

    this.memorySafety = memorySafety;
    log.info('✓ Memory Safety initialized', {
      canaries: memorySafety.getStatus().heapCanaries +
        memorySafety.getStatus().closureCanaries +
        memorySafety.getStatus().nativeCanaries,
    });

    // ═══════════════════════════════════════════════════════════════════════
    // TEMPORAL CODE SIGNING — GPS-bound signatures with auto-expiry
    // ═══════════════════════════════════════════════════════════════════════
    // Traditional code signing: sign once, valid forever (until compromise).
    // Temporal signing: signatures BREATHE — bound to GPS time, auto-expire.
    //
    // This forces:
    // - Regular re-attestation of releases
    // - Leaked/stolen signatures become useless after expiry
    // - Nodes reject code signed outside the trust window
    // ═══════════════════════════════════════════════════════════════════════
    log.info('[SIGN] Initializing Temporal Code Signing...');

    const temporalSigner = getTemporalSigner({
      timeSource: this.timeSourceDetector,
      networkId: this.networkId || this._identity?.network?.name || 'yakmesh',
    });

    // Bind GPS time source if available
    if (this.timeSourceDetector) {
      temporalSigner.bindTimeSource(this.timeSourceDetector);
    }

    // Register as SANGHA component (signer participates in collective)
    joinSangha('sign', temporalSigner, async () => {
      return temporalSigner.getStatus();
    });

    this.temporalSigner = temporalSigner;
    log.info('✓ Temporal Signing initialized', temporalSigner.getStatus());

    // ═══════════════════════════════════════════════════════════════════════
    // KARMA RATE LIMITER — Trust-adaptive rate limiting + input validation
    // ═══════════════════════════════════════════════════════════════════════
    // Traditional rate limiting: Fixed thresholds for everyone.
    // KARMA-adaptive: Throughput scales with earned reputation.
    //
    // - Unknown peers: 10 req/min (strict)
    // - Hostile (KARMA 0-10): 2 req/min (almost blocked)
    // - Low (KARMA 11-30): 25 req/min
    // - Medium (KARMA 31-60): 50 req/min
    // - High (KARMA 61-85): 100 req/min
    // - Excellent (KARMA 86-100): 200 req/min
    //
    // This creates economic incentive: good behavior → higher throughput.
    // ═══════════════════════════════════════════════════════════════════════
    log.info('[RATE] Initializing KARMA Rate Limiter...');

    const rateLimiter = getKarmaRateLimiter();

    // Bind to KARMA trust model for reputation lookups
    if (this.karmaTrust) {
      rateLimiter.bindKarmaTrust(this.karmaTrust);
    }

    // Bind to SANGHA for collective response
    rateLimiter.bindSangha(sangha);

    // Register as SANGHA component
    joinSangha('rate', rateLimiter, async () => {
      return rateLimiter.getState();
    });

    // Forward block events
    rateLimiter.on('blocked', ({ peerId, reason }) => {
      log.warn('[BLOCKED] Peer rate-limited', { peerId: peerId.slice(0, 16), reason });
    });

    // Periodic cleanup of stale buckets
    setInterval(() => rateLimiter.cleanup(), 300000); // Every 5 minutes

    this.rateLimiter = rateLimiter;
    log.info('✓ KARMA Rate Limiter initialized', rateLimiter.getStatus());

    // ═══════════════════════════════════════════════════════════════════════
    // SECURE CONFIG — Oracle-attested configuration management
    // ═══════════════════════════════════════════════════════════════════════
    // Traditional secure defaults: Ship with good defaults, hope they stick.
    // Oracle-attested config: Configuration is hashed and cryptographically
    // verified. Any deviation from the secure profile is detected.
    //
    // Profiles:
    // - PARANOID: Maximum security, minimal attack surface
    // - HARDENED: Production-ready security (default)
    // - STANDARD: Balanced security
    // - DEVELOPMENT: Relaxed for local dev (warnings only)
    // ═══════════════════════════════════════════════════════════════════════
    log.info('[CFG] Initializing Secure Config...');

    const secureConfig = getSecureConfig(); // Uses YAKMESH_SECURITY_PROFILE env or HARDENED

    // Bind to SANGHA for collective verification
    secureConfig.bindSangha(sangha);

    // Register as SANGHA component
    joinSangha('config', secureConfig, async () => {
      return secureConfig.getState();
    });

    // Forward deviation events
    secureConfig.on('deviation', ({ profileLevel, deviations }) => {
      log.warn('[WARN] Config deviation from secure profile', {
        profile: profileLevel,
        deviations: deviations.length,
      });
    });

    this.secureConfig = secureConfig;
    log.info('✓ Secure Config initialized', secureConfig.getStatus());
  }

  // =========================================================================
  // SCHEDULED WORKLOADS — route ML inference through ComputeScheduler
  // =========================================================================

  /**
   * Schedule a ternary trust classification through the compute scheduler.
   * Routes KARMA trust scores through the TernaryInferenceAdapter for
   * SST-family-aware classification (NEGATIVE/NEUTRAL/POSITIVE mapping).
   * 
   * NORMAL priority — enrichment task, not security-critical path.
   *
   * @param {string} nodeId — peer to classify
   * @param {number} trustScore — 0-100 trust score from KARMA
   * @returns {Promise<{ outcome, device, result, execMs, waitMs }>}
   */
  _scheduledTernaryTrustClassification(nodeId, trustScore) {
    const executor = () => this.ternaryInference.classifyTrust(trustScore);
    return accel.scheduler.submit({
      type: 'ternary-trust',
      priority: accel.Priority.NORMAL,
      affinity: accel.Affinity.NPU_PREFERRED,
      timeoutMs: 2000,
      inputSize: 4,
      executors: { npu: executor, gpu: executor, cpu: executor },
    });
  }

  /**
   * Schedule a batch YPC-27 checksum verification via the compute scheduler.
   * Wraps the BatchChecksumVerifier for protocol-level packet integrity.
   * 
   * HIGH priority — checksum verification is integrity-critical.
   *
   * @param {string} domain — protocol domain (e.g., 'STUPA', 'NAKPAK')
   * @param {string} nodeId — peer node ID for seed derivation
   * @param {Uint8Array} data — packet data to verify
   * @param {Object} checksum — expected checksum from wire
   * @returns {Promise<boolean>}
   */
  async _scheduledChecksumVerify(domain, nodeId, data, checksum) {
    return batchChecksumVerifier.enqueue(domain, nodeId, data, checksum);
  }

  /**
   * Schedule a PRAHARI entropy quality check through the compute scheduler.
   * CRITICAL priority — entropy degradation is a security emergency.
   *
   * @param {Uint8Array} data — raw bytes to score
   * @returns {Promise<{ outcome, device, result, execMs, waitMs }>}
   */
  _scheduledEntropyCheck(data) {
    const executor = () => prahari.scoreEntropy(data);
    return accel.scheduler.submit({
      type: 'entropy-sentinel',
      priority: accel.Priority.CRITICAL,
      affinity: accel.Affinity.NPU_PREFERRED,
      timeoutMs: 2000,
      inputSize: data?.length || 256,
      executors: { npu: executor, gpu: executor, cpu: executor },
    });
  }

  /**
   * Schedule a SAKSHI anomaly assessment through the compute scheduler.
   * HIGH priority — anomaly detection is security-sensitive.
   *
   * @param {string} nodeId — peer to assess
   * @param {Object} context — additional context features for the ONNX model
   * @returns {Promise<{ outcome, device, result, execMs, waitMs }>}
   */
  _scheduledAnomalyAssessment(nodeId, context = {}) {
    const executor = () => this.velocityMonitor.assessNode(nodeId, context);
    return accel.scheduler.submit({
      type: 'sakshi-anomaly',
      priority: accel.Priority.HIGH,
      affinity: accel.Affinity.NPU_PREFERRED,
      timeoutMs: 3000,
      inputSize: 48,   // 12 × float32
      executors: { npu: executor, gpu: executor, cpu: executor },
    });
  }

  /**
   * Schedule a KARMA trust prediction through the compute scheduler.
   * HIGH priority — trust decisions affect network security.
   *
   * @param {Object} evidence — KarmaEvidence instance
   * @returns {Promise<{ outcome, device, result, execMs, waitMs }>}
   */
  _scheduledTrustPrediction(evidence) {
    const executor = () => this.karmaModel.predictTrustLevel(evidence);
    return accel.scheduler.submit({
      type: 'karma-trust',
      priority: accel.Priority.HIGH,
      affinity: accel.Affinity.NPU_PREFERRED,
      timeoutMs: 3000,
      inputSize: 56,   // 14 × float32
      executors: { npu: executor, gpu: executor, cpu: executor },
    });
  }

  /**
   * Schedule batch ML-DSA-65 signature verification through the scheduler.
   * HIGH priority — signature verification is security-critical.
   *
   * @param {Uint8Array} signature
   * @param {Uint8Array} message
   * @param {Uint8Array} publicKey
   * @returns {Promise<{ outcome, device, result, execMs, waitMs }>}
   */
  _scheduledBatchVerify(signature, message, publicKey) {
    const executor = () => accel.batchVerify.enqueue(signature, message, publicKey);
    return accel.scheduler.submit({
      type: 'batch-verify',
      priority: accel.Priority.HIGH,
      affinity: accel.Affinity.GPU_PREFERRED,
      timeoutMs: 5000,
      inputSize: (signature?.length || 0) + (message?.length || 0) + (publicKey?.length || 0),
      executors: { gpu: executor, npu: executor, cpu: executor },
    });
  }

  /**
   * Start periodic scheduled workloads that exercise the compute scheduler.
   * Called once during boot after all subsystems are initialized.
   */
  _startScheduledWorkloads() {
    // ── Periodic entropy health check (every 30s) ──
    // Generates fresh random bytes and scores them through STEADYWATCH sentinel.
    // Detects entropy source degradation before it impacts ANNEX keygen.
    this._entropyCheckTimer = setInterval(async () => {
      try {
        const sample = crypto.randomBytes(256);
        const { result } = await this._scheduledEntropyCheck(sample);
        if (result && result.score < 0.6) {
          log.warn(`⚠️ PRAHARI: Entropy quality degraded (score=${result.score.toFixed(3)}, verdict=${result.verdict})`);
        }
      } catch (err) {
        // Scheduler rejection (queue full) is fine — non-fatal
        if (err?.outcome !== 'rejected') {
          log.debug(`Entropy check error: ${err.message || err.reason || 'unknown'}`);
        }
      }
    }, 30_000);
    if (this._entropyCheckTimer.unref) this._entropyCheckTimer.unref();

    // ── Periodic peer assessment sweep (every 60s) ──
    // Deep-assesses the 5 most active peers via SAKSHI anomaly model.
    // Catches slow-burn attacks that velocity z-scores alone miss.
    this._peerAssessTimer = setInterval(async () => {
      if (!this.velocityMonitor || !this.mesh) return;
      const peers = this.mesh.getPeers ? this.mesh.getPeers() : [];
      // Assess up to 5 peers per sweep — don't flood the scheduler
      const batch = peers.slice(0, 5);
      for (const peerId of batch) {
        try {
          const karmaEvidence = this.karmaModel?.getEvidence(peerId);
          const context = {
            karmaScore: karmaEvidence?.trustScore ? karmaEvidence.trustScore / 100 : 0.5,
            uptimePercent: 0.5,
            networkAgeDays: karmaEvidence ? (aguwa.now() - (karmaEvidence.firstSeen || aguwa.now())) / 86400000 : 0,
          };
          const { result } = await this._scheduledAnomalyAssessment(peerId, context);
          if (result && result.anomalyScore > 0.7) {
            log.warn(`👁️ SAKSHI: High anomaly score for ${peerTag(peerId)} (score=${result.anomalyScore.toFixed(3)}, source=${result.source})`);
          }
        } catch {
          // Non-fatal — scheduler may have rejected the task
        }
      }
    }, 60_000);
    if (this._peerAssessTimer.unref) this._peerAssessTimer.unref();

    log.info('✓ Scheduled workloads: entropy-sentinel(30s) + peer-assessment(60s) via ComputeScheduler');
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

    this.kommWss = new WebSocketServer({ noServer: true, maxPayload: 1048576 }); // 1MB max message size

    // Per-client ANNEX sessions for PQ encryption
    const kommAnnexSessions = new Map(); // ws → ServerAnnexSession

    /**
     * secureSend — encrypt outbound KOMM messages via ANNEX when session exists
     */
    const secureSend = (ws, data) => {
      if (ws.readyState !== 1) return; // OPEN
      const session = kommAnnexSessions.get(ws);
      if (session && !session.isExpired()) {
        try {
          const encrypted = session.encrypt(typeof data === 'string' ? data : JSON.stringify(data));
          ws.send(JSON.stringify({ type: ANNEX_HANDSHAKE_TYPE.ENCRYPTED, payload: encrypted }));
        } catch {
          // Encryption failed — drop message (no plaintext fallback)
          log.warn('KOMM ANNEX encrypt failed — message dropped');
        }
      } else {
        // No ANNEX session yet — send plaintext (only during handshake/migration)
        ws.send(typeof data === 'string' ? data : JSON.stringify(data));
      }
    };

    // Handle upgrade requests for /komm/ws path
    this.http.on('upgrade', (request, socket, head) => {
      // Catch TCP errors on the raw socket during upgrade — prevents
      // ECONNRESET from bubbling up as an uncaught exception
      socket.on('error', (err) => {
        log.debug('Upgrade socket error (benign)', { code: err.code, msg: err.message });
      });

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

    // Dashboard-subscribed clients (subset of kommClients)
    const dashboardSubscribers = new Set();

    this.kommWss.on('connection', (ws, request) => {
      kommClients.add(ws);
      log.debug('📡 KOMM WS client connected');

      ws.on('close', () => {
        kommClients.delete(ws);
        dashboardSubscribers.delete(ws);
        // Destroy ANNEX session on close — zero key material
        const session = kommAnnexSessions.get(ws);
        if (session) { session.destroy(); kommAnnexSessions.delete(ws); }
        log.debug('📡 KOMM WS client disconnected');
      });

      ws.on('error', (err) => {
        log.warn({ code: err.code, message: err.message }, 'KOMM WebSocket error');
        kommClients.delete(ws);
        dashboardSubscribers.delete(ws);
        const session = kommAnnexSessions.get(ws);
        if (session) { session.destroy(); kommAnnexSessions.delete(ws); }
      });

      // Handle incoming messages from client
      ws.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw.toString());

          // ── ANNEX handshake layer (before any application logic) ──
          if (msg.type === ANNEX_HANDSHAKE_TYPE.PUBLIC_KEY) {
            const session = new ServerAnnexSession({
              localId: peerTag(this.identity.identity.nodeId),
              remoteId: msg.clientId || 'komm-client',
            });
            const result = session.handlePublicKey(msg.publicKey);
            kommAnnexSessions.set(ws, session);
            ws.send(JSON.stringify({
              type: ANNEX_HANDSHAKE_TYPE.ENCAPSULATED,
              ciphertext: result.ciphertext,
              serverId: peerTag(this.identity.identity.nodeId),
              sessionId: msg.sessionId,
            }));
            log.debug('📡 KOMM ANNEX handshake complete (ML-KEM-768)');
            return;
          }

          if (msg.type === 'annex:rekey_ack') {
            const session = kommAnnexSessions.get(ws);
            if (session) {
              session.rekey(msg.publicKey);
              log.debug('📡 KOMM ANNEX rekeyed');
            }
            return;
          }

          if (msg.type === ANNEX_HANDSHAKE_TYPE.ENCRYPTED) {
            const session = kommAnnexSessions.get(ws);
            if (!session) return;
            const plaintext = session.decrypt(msg.payload);
            const decrypted = JSON.parse(plaintext);
            // Check if rekey needed
            if (session.isNearingExpiry()) {
              secureSend(ws, { type: 'annex:rekey', reason: 'threshold' });
            }
            this._handleKommWsMessage(decrypted, ws, secureSend);
            return;
          }

          // Plaintext fallback (backward compat during migration)
          this._handleKommWsMessage(msg, ws, secureSend);
        } catch {
          secureSend(ws, { error: 'Invalid message' });
        }
      });

      // Send welcome (may be plaintext if ANNEX not yet established)
      secureSend(ws, {
        type: 'welcome',
        nodeId: peerTag(this.identity.identity.nodeId),
        capabilities: ['katha', 'vani', 'yurt', 'dashboard', 'servers'],
      });
    });

    // Broadcast helper — now encrypts per-client via ANNEX
    const broadcastKomm = (type, data) => {
      const payload = { type, data, ts: aguwa.now() };
      for (const client of kommClients) {
        secureSend(client, payload);
      }
    };

    // ── Dashboard push infrastructure ──────────────────────────────────

    /**
     * Gather a full dashboard snapshot — same data the HTTP dashboard polls
     * Returns { node, peers, metrics, gossip, discovered }
     */
    const gatherDashboardSnapshot = () => {
      const startTime = this._startTime || aguwa.now();
      const uptime = Math.floor((aguwa.now() - startTime) / 1000);

      // Build lightweight metrics (mirrors /metrics endpoint)
      const oracleInfo = this.oracle ? (() => {
        const integrity = this.oracle.verifySelfIntegrity();
        return {
          status: integrity.valid ? 'healthy' : 'compromised',
          valid: integrity.valid,
          networkName: this.genesisNetwork?.networkName || null,
          networkId: this.genesisNetwork?.networkId || null,
          fingerprint: this.genesisNetwork?.fingerprint || null,
          verifiedPeers: this.codeProof?.getVerifiedPeers()?.length || 0,
        };
      })() : null;

      const websiteInfo = this.websiteAdapter ? {
        status: 'active',
        websites: this.websiteAdapter.manifests.size,
        uniqueSites: this.websiteAdapter.domains.size || 1,
        domains: this.websiteAdapter.domains.size,
        filesServed: this.websiteAdapter.stats.filesServed,
        bytesServed: this.websiteAdapter.stats.bytesServed,
        publisherDoko: this.websiteAdapter.publisherDoko || null,
      } : { status: 'uninitialized' };

      const cryptoInfo = this._cryptoSummary || {
        levelName: 'NIST Level 3',
        signatureAlgorithm: 'ML-DSA-65',
        backupSignatureAlgorithm: 'SLH-DSA-SHA2-192f',
        kemAlgorithm: 'ML-KEM-768',
        classicalSecurity: '192-bit',
        quantumSecurity: '128-bit',
        routingSecurity: '256-bit (162T)',
        nistStandards: ['FIPS 203 (ML-KEM)', 'FIPS 204 (ML-DSA)', 'FIPS 205 (SLH-DSA)'],
      };

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

      // NAMCHE security gate status
      let namcheInfo = null;
      if (this.namcheGateway) {
        namcheInfo = this.namcheGateway.getStatus();
      } else {
        namcheInfo = { gates: GATE_NAMES, status: 'uninitialized', gateCount: 7 };
      }

      // DOKO identity status
      let dokoInfo = null;
      if (this.dokoRegistry) {
        dokoInfo = this.dokoRegistry.getStats();
      } else {
        dokoInfo = { status: 'uninitialized', types: Object.keys(DOKOTypes) };
      }

      return {
        node: this.identity.getPublicIdentity(),
        peers: this.mesh.getPeers(),
        metrics: {
          node: {
            id: this.identity?.identity?.nodeId || null,
            name: this.config?.node?.name || 'unknown',
            version: '2.9.0',
            uptime,
            uptimeFormatted: formatUptime(uptime),
          },
          crypto: cryptoInfo,
          oracle: oracleInfo,
          website: websiteInfo,
          time: timeInfo,
          security: {
            namche: namcheInfo,
            doko: dokoInfo,
          },
        },
        gossip: this.gossip.getStats(),
        discovered: this.gossip.getKnownPeers(),
      };
    };

    /**
     * Push dashboard:update to all subscribed clients.
     * Debounced — event-triggered pushes coalesce within 2 s window.
     */
    let _dashPushTimer = null;
    const pushDashboardUpdate = (immediate = false) => {
      if (dashboardSubscribers.size === 0) return;

      const send = () => {
        _dashPushTimer = null;
        if (dashboardSubscribers.size === 0) return;
        const snapshot = gatherDashboardSnapshot();
        const payload = { type: 'dashboard:update', data: snapshot, ts: aguwa.now() };
        for (const sub of dashboardSubscribers) {
          secureSend(sub, payload);
        }
      };

      if (immediate) {
        if (_dashPushTimer) { clearTimeout(_dashPushTimer); _dashPushTimer = null; }
        send();
      } else {
        // Debounce: coalesce rapid events into one push
        if (!_dashPushTimer) {
          _dashPushTimer = setTimeout(send, 2000);
        }
      }
    };

    // Store references for use in _handleKommWsMessage
    this._dashboardSubscribers = dashboardSubscribers;
    this._pushDashboardUpdate = pushDashboardUpdate;
    this._gatherDashboardSnapshot = gatherDashboardSnapshot;

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

    // ── Wire mesh events → dashboard push (debounced) ──────────────────
    if (this.mesh) {
      this.mesh.on('peer:connected', () => pushDashboardUpdate());
      this.mesh.on('peer:disconnected', () => pushDashboardUpdate());
    }

    // 10 s heartbeat — keeps dashboards fresh even when nothing changes
    setInterval(() => pushDashboardUpdate(true), 10_000);

    log.info('✓ KOMM WebSocket initialized at /komm/ws (ANNEX PQ-encrypted, dashboard push)');
  }

  /**
   * Handle incoming KOMM WS messages from clients
   */
  _handleKommWsMessage(msg, ws, secureSend) {
    const { type, data } = msg;

    switch (type) {
      // ══════════════════════════════════════════════════════════════════
      // KATHA (Chat) Handlers
      // ══════════════════════════════════════════════════════════════════

      case 'katha:auth':
        // Client authentication — store username for this connection
        ws._kathaUser = {
          username: msg.username || data?.username || 'anon',
          userId: msg.userId || data?.userId || `user_${aguwa.now()}`,
          clientType: msg.clientType || 'web',
        };
        secureSend(ws, {
          type: 'katha:auth-ok',
          userId: ws._kathaUser.userId,
          username: ws._kathaUser.username,
        });
        log.debug(`📡 KOMM client authenticated: ${ws._kathaUser.username}`);
        break;

      case 'katha:list-channels':
        // Return list of channels
        const channels = [];
        if (this.kathaHub?.channels) {
          for (const [id, channel] of this.kathaHub.channels) {
            channels.push({
              id,
              name: channel.name || id,
              type: channel.type || 'text',
              memberCount: channel.members?.size || 0,
            });
          }
        }
        // Add default channels if none exist
        if (channels.length === 0) {
          channels.push(
            { id: 'general', name: 'general', type: 'text', memberCount: 1 },
            { id: 'random', name: 'random', type: 'text', memberCount: 0 },
          );
        }
        secureSend(ws, { type: 'katha:channels', channels });
        break;

      case 'katha:join':
        // Join a channel
        const channelId = data?.channelId || msg.channelId;
        if (channelId && this.kathaHub?.join) {
          this.kathaHub.join(channelId, ws._kathaUser);
        }
        // Get channel messages
        const channel = this.kathaHub?.channels?.get(channelId);
        const messages = channel?.getMessages?.({ limit: 50 }) || [];
        const members = channel?.members ? Array.from(channel.members.values()) : [];
        secureSend(ws, {
          type: 'katha:joined',
          channelId,
          messages,
          members,
        });
        break;

      case 'katha:send':
        // Process and broadcast chat message
        const sendData = {
          channelId: data.channelId,
          messageId: data.messageId || `msg_${aguwa.now()}_${Math.random().toString(36).slice(2)}`,
          userId: ws._kathaUser?.userId || data.userId,
          username: ws._kathaUser?.username || data.username,
          content: data.content,
          timestamp: new Date().toISOString(),
          type: data.type || 'katha:text',
        };

        // Store message (if kathaHub supports it)
        if (this.kathaHub?.send) {
          this.kathaHub.send(sendData);
        }

        // Broadcast to all KOMM clients (including sender for confirmation)
        this.kommWss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN && client._kathaUser) {
            client.send(JSON.stringify({ type: 'katha:message', data: sendData }));
          }
        });
        break;

      case 'katha:typing':
        // Broadcast typing indicator to channel members
        const typingData = {
          channelId: data.channelId,
          userId: ws._kathaUser?.userId || data.userId,
          username: ws._kathaUser?.username || data.username,
          isTyping: data.isTyping !== false,
        };

        if (this.kathaHub?.setTyping) {
          this.kathaHub.setTyping(typingData);
        }

        // Broadcast to all KOMM clients in the same channel (except sender)
        this.kommWss.clients.forEach(client => {
          if (client !== ws && client.readyState === WebSocket.OPEN && client._kathaUser) {
            client.send(JSON.stringify({ type: 'katha:typing', data: typingData }));
          }
        });
        break;

      case 'katha:reaction':
        // Toggle reaction on a message
        const reactionData = {
          channelId: data.channelId,
          messageId: data.messageId,
          emoji: data.emoji,
          userId: ws._kathaUser?.userId || data.userId,
        };

        // Store reaction (if kathaHub supports it)
        if (this.kathaHub?.toggleReaction) {
          this.kathaHub.toggleReaction(reactionData);
        }

        // Broadcast to all KOMM clients (including sender for confirmation)
        this.kommWss.clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN && client._kathaUser) {
            client.send(JSON.stringify({ type: 'katha:reaction', data: reactionData }));
          }
        });
        break;

      // ══════════════════════════════════════════════════════════════════
      // YURT (Rooms) Handlers  
      // ══════════════════════════════════════════════════════════════════

      case 'yurt:browse':
        // Browse available rooms
        const rooms = [];
        if (this.yurtHub?.directory?.entries) {
          for (const [id, entry] of this.yurtHub.directory.entries) {
            rooms.push({
              id,
              name: entry.name || id,
              description: entry.description || '',
              memberCount: entry.memberCount || 0,
              isPublic: entry.isPublic !== false,
            });
          }
        }
        secureSend(ws, { type: 'yurt:rooms', rooms });
        break;

      // ══════════════════════════════════════════════════════════════════
      // VANI (Voice/Video) Handlers
      // ══════════════════════════════════════════════════════════════════

      case 'vani:signal':
        if (this.vaniHub?.signal) {
          this.vaniHub.signal(data);
        }
        break;

      case 'vani:call':
        if (this.vaniHub?.initiateCall) {
          this.vaniHub.initiateCall(data).then(result => {
            secureSend(ws, { type: 'vani:callResult', data: result });
          }).catch(() => { });
        }
        break;

      // ══════════════════════════════════════════════════════════════════
      // General
      // ══════════════════════════════════════════════════════════════════

      case 'dashboard:subscribe':
        // Register this client for real-time dashboard pushes
        if (this._dashboardSubscribers) {
          this._dashboardSubscribers.add(ws);
          log.debug('📡 Dashboard subscriber registered');
          // Send an immediate full snapshot
          const snapshot = this._gatherDashboardSnapshot();
          secureSend(ws, { type: 'dashboard:update', data: snapshot, ts: aguwa.now() });
        }
        break;

      case 'dashboard:unsubscribe':
        if (this._dashboardSubscribers) {
          this._dashboardSubscribers.delete(ws);
          log.debug('📡 Dashboard subscriber removed');
        }
        break;

      case 'ping':
        secureSend(ws, { type: 'pong', ts: aguwa.now() });
        break;

      // ══════════════════════════════════════════════════════════════════
      // SERVER DIRECTORY — C2C Lighthouse (query via encrypted WS)
      // ══════════════════════════════════════════════════════════════════

      case 'servers:query': {
        // Query the C2C server directory
        if (!this.serverDirectory) {
          secureSend(ws, { type: 'servers:list', servers: [], stats: {}, serverTime: aguwa.now() });
          break;
        }
        const status = data?.status || null;
        const limit = data?.limit || 100;
        const directory = this.serverDirectory.getDirectory({ status, limit });
        const stats = this.serverDirectory.getStats();
        secureSend(ws, { type: 'servers:list', servers: directory, stats, serverTime: aguwa.now() });
        break;
      }

      case 'servers:detail': {
        // Get single server detail
        const nodeId = data?.nodeId;
        if (!nodeId || !this.serverDirectory) {
          secureSend(ws, { type: 'servers:detail', server: null, error: nodeId ? 'Directory not ready' : 'nodeId required' });
          break;
        }
        const server = this.serverDirectory.getServer(nodeId);
        secureSend(ws, { type: 'servers:detail', server: server || null, error: server ? null : 'Server not found' });
        break;
      }

      default:
        log.debug(`📡 Unknown KOMM message type: ${type}`);
    }
  }

  /**
   * Handle oracle-validated content from peers
   */
  _handleOracleContent(data, origin) {
    const { sealedPackage, attestations } = data;

    // Verify the peer is running valid code
    if (!this.codeProof.isPeerVerified(origin)) {
      log.warn(`⚠️ Received content from unverified peer ${peerTag(origin)}`);
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
      log.debug(`🌐 Peer ${peerTag(origin)} verified on same network: ${handshake.name}`);
    } else {
      log.debug(`⚠️ Peer ${peerTag(origin)} on different network: ${handshake.name} (${handshake.shortId})`);
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

  /**
   * Resolve a peer's ML-DSA-65 public key from mesh registries.
   * Mirrors the annex._getPeerPublicKey() pattern:
   *   1. WS peers (direct connections)
   *   2. Relay peer keys (signed relay registration)
   *   3. SHERPA registry (discovered peers)
   * 
   * Returns hex public key string or null if unknown peer.
   */
  _resolvePeerPublicKey(nodeId) {
    // 1. Direct WS peer (most trusted — active connection with verified HELLO)
    if (this.mesh?.peers) {
      const peer = this.mesh.peers.get(nodeId);
      if (peer?.identity?.publicKey) return peer.identity.publicKey;
    }
    // 2. Relay registration keys (signed during relay handshake)
    if (this.mesh?._relayPeerKeys) {
      const key = this.mesh._relayPeerKeys.get(nodeId);
      if (key) return key;
    }
    // 3. SHERPA discovery registry (populated during beacon exchange)
    if (this.mesh?.sherpa?.registry) {
      const regPeer = this.mesh.sherpa.registry.get(nodeId);
      if (regPeer?.publicKey) return regPeer.publicKey;
    }
    return null;
  }

  async _startHttpServer() {
    const app = express();
    this.app = app;  // Store for PeerQuanta endpoints

    // Enable strict routing: /docs and /docs/ are different routes
    app.set('strict routing', true);

    // SECURITY: Do NOT set 'trust proxy'. This is a P2P mesh node, not
    // behind a reverse proxy. Setting trust proxy lets remote attackers
    // forge req.ip via X-Forwarded-For headers. Rate limiting uses
    // validate: { xForwardedForHeader: false } to avoid this class of attack.
    // If deployed behind a known proxy, configure trustedProxies explicitly.

    app.use(express.json({ limit: '1mb' }));  // Limit payload size

    // =========================================
    // SECURITY: Rate Limiting (DoS Protection)
    // =========================================

    // Skip rate limiting for localhost — dashboard, yakapp, and CLI all hit the
    // local node heavily; throttling them degrades the user experience.
    // Remote IPs still get full rate limiting.
    const isLoopback = (req) => {
      // SECURITY: Use raw socket address only — req.ip trusts X-Forwarded-For
      const ip = req.socket?.remoteAddress || '';
      return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
    };

    // General rate limit: 100 requests per minute per IP (remote only)
    const generalLimiter = rateLimit({
      windowMs: 60 * 1000,  // 1 minute
      max: 100,
      skip: isLoopback,
      message: { error: 'Too many requests, please try again later' },
      standardHeaders: true,
      legacyHeaders: false,
      validate: { xForwardedForHeader: false },
    });

    // Strict rate limit for write operations: 20 per minute (remote only)
    const writeLimiter = rateLimit({
      windowMs: 60 * 1000,
      max: 20,
      skip: isLoopback,
      message: { error: 'Too many write requests, please slow down' },
      standardHeaders: true,
      legacyHeaders: false,
      validate: { xForwardedForHeader: false },
    });

    // Apply general limiter to all routes
    app.use(generalLimiter);

    // CORS — restricted to localhost and configured origins
    const httpPort = this.boundHttpPort || this.config.network.httpPort;
    const allowedOrigins = new Set([
      `http://localhost:${httpPort}`,
      'http://localhost:3090',
      `http://127.0.0.1:${httpPort}`,
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
    // Validates that write requests from peers include a valid ML-DSA-65 signature.
    // Uses real socket address — NOT req.ip — to prevent X-Forwarded-For spoofing.
    // Public key resolved from mesh peer registry, not from nodeId string.
    const requirePeerAuth = (req, res, next) => {
      const nodeId = req.headers['x-node-id'];
      const sig = req.headers['x-node-signature'];
      const ts = req.headers['x-node-timestamp'];

      // Use the RAW socket address, immune to X-Forwarded-For spoofing.
      // req.ip respects 'trust proxy' and can be forged — never use it for auth.
      const rawIP = req.socket?.remoteAddress;
      const isLocal = rawIP === '127.0.0.1' || rawIP === '::1' || rawIP === '::ffff:127.0.0.1';
      if (isLocal) {
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
      const drift = Math.abs(aguwa.now() - parseInt(ts, 10));
      if (isNaN(drift) || drift > MAX_AUTH_DRIFT_MS) {
        return res.status(401).json({ error: 'Request timestamp too old or invalid' });
      }

      // Resolve the ACTUAL public key for this nodeId from mesh peer registry.
      // The annex._getPeerPublicKey pattern: peers → _relayPeerKeys → sherpa.registry
      const peerPublicKey = this._resolvePeerPublicKey(nodeId);
      if (!peerPublicKey) {
        return res.status(403).json({ error: 'Unknown peer — no public key on record' });
      }

      // Verify ML-DSA-65 signature over (nodeId + timestamp + body hash)
      try {
        const bodyStr = JSON.stringify(req.body || {});
        const payload = `${nodeId}:${ts}:${bodyStr}`;
        const verified = this.identity.verify(payload, sig, peerPublicKey);
        if (!verified) {
          return res.status(403).json({ error: 'Invalid peer signature' });
        }
        req.authenticatedPeer = nodeId;
        req.authenticatedPeerKey = peerPublicKey;
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
    // UNIFIED PUBLIC WEB ROOT
    // =========================================
    // Single static mount for all public assets:
    //   public/dashboard/  — web dashboard UI
    //   public/assets/     — logos and brand assets
    //   public/c2c/assets/ — C2C game art (build artifact)
    //   public/yakai/      — YakAI portraits (build artifact)
    // Build with: npm run build:public
    const publicDir = join(import.meta.dirname, '..', 'public');
    if (existsSync(publicDir)) {
      app.use(express.static(publicDir, {
        maxAge: '7d',
        etag: true,
        fallthrough: true,
        index: false,           // Don't auto-serve index.html at /
        redirect: false,        // Don't redirect /dashboard → /dashboard/
      }));
    }

    // =========================================
    // PUBLIC CONTENT API (No Auth for reads)
    // =========================================

    // Mount content API at /content
    const contentAPI = createContentAPI(this.contentStore, {
      writeLimiter,
      readLimiter: generalLimiter,
      validateString,
      requirePeerAuth,
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
        requirePeerAuth,
      });
      app.use('/darshan', darshanRouter);
      log.info('📡 DARSHAN API mounted at /darshan');
    }

    // =========================================
    // PROFILE — Unified Mesh Profiles
    // =========================================

    const profileRouter = createProfileAPI({
      replication: this.replication,
      gossip: this.gossip,
      identity: this.identity,
      writeLimiter,
    });
    app.use('/profile', profileRouter);
    log.info('📡 Profile API mounted at /profile');

    // =========================================
    // TME — Temporal Mesh Encoding
    // =========================================

    if (this.tmeRouter) {
      app.use('/tme', this.tmeRouter);
      log.info('📡 TME API mounted at /tme');
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
          nodeId: peerTag(this.identity.identity.nodeId),
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
    // ANNEX + JHILKE Status Endpoint
    // =========================================

    app.get('/annex/status', (req, res) => {
      const annex = this.mesh?.annex;
      const jhilke = this.mesh?.jhilke;

      if (!annex) {
        return res.json({ active: false, reason: 'ANNEX not initialized' });
      }

      const sessions = annex.listAnnexes().map(s => ({
        ...s,
        nodeId: peerTag(s.nodeId),
      }));

      const jhilkeStats = jhilke?.getStats() || null;

      res.json({
        active: true,
        nodeId: peerTag(this.identity.identity.nodeId),
        stats: annex.getStats(),
        sessions,
        jhilke: jhilkeStats ? {
          ...jhilkeStats,
          coordinatorActive: true,
        } : { coordinatorActive: false },
      });
    });

    // =========================================
    // Ternary Harmonization Status Endpoint
    // =========================================

    app.get('/ternary/status', (req, res) => {
      res.json({
        active: true,
        address162t: this.tritAddress?.toString() || null,
        routing: this.ternaryRouter?.getStatus() || null,
        batchChecksum: batchChecksumVerifier.telemetry,
        ternaryInference: !!this.ternaryInference,
      });
    });

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

    // Serve dashboard — falls through to public/dashboard/index.html via static mount
    app.get('/dashboard', (req, res) => {
      const dashboardPath = join(import.meta.dirname, '..', 'public', 'dashboard', 'index.html');
      if (existsSync(dashboardPath)) {
        res.sendFile(dashboardPath);
      } else {
        // Fallback to legacy location
        res.sendFile('dashboard/index.html', { root: import.meta.dirname + '/..' });
      }
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
        persistentId: this.identity.getPersistentId(),  // 162T identity across code upgrades
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
        prahari: prahari.getStatus(),
        commitReveal: this.commitReveal ? this.commitReveal.getStats() : null,
        timeSource: this.timeSource ? this.timeSource.getStatus() : null,
        aguwa: {
          health: aguwa.health(),
          orderParameter: +aguwa.orderParameter().toFixed(4),
          peerCount: aguwa.peers.size,
          correctionMs: aguwa._correctionMs,
          divergentPeers: aguwa.detectDivergentPeers().length,
        },
        security: this.mesh.getSecurityStats(),
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
    // COMPUTE SCHEDULER: Heterogeneous GPU/NPU/CPU
    // =========================================
    app.get('/scheduler', (req, res) => {
      res.json(accel.scheduler.getStatus());
    });

    app.get('/scheduler/training-data', (req, res) => {
      const n = Math.min(parseInt(req.query.n) || 100, 5000);
      res.json(accel.scheduler.getTrainingData(n));
    });

    // =========================================
    // PRAHARI: Mesh-Consensus Entropy Status
    // =========================================
    app.get('/prahari', (req, res) => {
      res.json({
        ...prahari.getStatus(),
        commitReveal: this.commitReveal ? this.commitReveal.getStats() : null,
      });
    });

    // Backward compat: /steadywatch still works
    app.get('/steadywatch', (req, res) => {
      res.json({
        ...prahari.getStatus(),
        commitReveal: this.commitReveal ? this.commitReveal.getStats() : null,
      });
    });

    // Domain-separated entropy seed for external consumers (Pondera Next, etc.)
    app.get('/prahari/seed', (req, res) => {
      const bytes = Math.max(1, Math.min(256, parseInt(req.query.bytes, 10) || 32));
      const rawLabel = String(req.query.label || 'GAME').slice(0, 64);
      const label = rawLabel.replace(/[^a-zA-Z0-9_-]/g, '');
      const domainLabel = 'PRAHARI-' + label;
      const seed = prahari.squeeze(bytes, domainLabel);
      res.json({
        hex: Buffer.from(seed).toString('hex'),
        bytes,
        label,
        absorbCount: prahari.getStatus().absorbCount,
      });
    });

    // =========================================
    // PUBLIC ENTROPY BEACON API (Paranoid Entropy Beacon)
    // Open CORS + generous rate limits for external entropy consumers
    // =========================================
    const publicBeaconLimiter = rateLimit({
      windowMs: 60 * 1000,
      max: 300,
      skip: isLoopback,
      standardHeaders: true,
      legacyHeaders: false,
      message: { error: 'Rate limit exceeded. Try again in a minute.' },
    });

    const openCors = (req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type');
      if (req.method === 'OPTIONS') return res.sendStatus(200);
      next();
    };

    app.get('/public/latest', publicBeaconLimiter, openCors, (req, res) => {
      if (!this.commitReveal) {
        return res.status(503).json({ error: 'Commit-reveal beacon not initialized' });
      }
      const pulse = this.commitReveal.getLatestPulse();
      if (!pulse) {
        return res.status(503).json({ error: 'No pulse available yet. Wait for the first round to complete.' });
      }
      res.json(pulse);
    });

    app.get('/public/:round', publicBeaconLimiter, openCors, (req, res) => {
      if (!this.commitReveal) {
        return res.status(503).json({ error: 'Commit-reveal beacon not initialized' });
      }
      const round = parseInt(req.params.round, 10);
      if (isNaN(round) || round < 1) {
        return res.status(400).json({ error: 'Invalid round number' });
      }
      const pulse = this.commitReveal.getPulse(round);
      if (!pulse) {
        return res.status(404).json({ error: 'Pulse not found for this round' });
      }
      res.json(pulse);
    });

    app.get('/public', publicBeaconLimiter, openCors, (req, res) => {
      if (!this.commitReveal) {
        return res.status(503).json({ error: 'Commit-reveal beacon not initialized' });
      }
      const limit = Math.min(1000, Math.max(1, parseInt(req.query.limit, 10) || 100));
      const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
      res.json({
        pulses: this.commitReveal.getPulseHistory(limit, offset),
        limit,
        offset,
      });
    });

    app.get('/info', publicBeaconLimiter, openCors, (req, res) => {
      if (!this.commitReveal) {
        return res.status(503).json({ error: 'Commit-reveal beacon not initialized' });
      }
      res.json(this.commitReveal.getGenesisInfo());
    });

    app.post('/public/verify', publicBeaconLimiter, openCors, (req, res) => {
      if (!this.commitReveal || !this.identity) {
        return res.status(503).json({ error: 'Beacon not initialized' });
      }
      const { round, randomness, timestamp, previous_signature, signature, public_key } = req.body;
      if (!signature || !randomness) {
        return res.status(400).json({ error: 'Missing signature or randomness in request body' });
      }
      const payload = JSON.stringify({
        round: round ?? null,
        randomness,
        timestamp: timestamp ?? null,
        previous_signature: previous_signature ?? null,
      });
      const pk = public_key || this.identity.identity.publicKey;
      const valid = this.identity.verify(payload, signature, pk);
      res.json({
        valid,
        round: round ?? null,
        verifiedAgainst: pk.slice(0, 32) + '...',
      });
    });

    // =========================================
    // SHERPA HTTP Relay: Mesh messaging over HTTP
    // =========================================
    // Allows nodes behind firewalls to exchange mesh messages via HTTP POST
    // instead of WebSocket. The PHP bridge on yakmesh.dev proxies to this.
    // Message flow: Remote Node → HTTPS POST yakmesh.dev/mesh/relay → PHP → localhost:<httpPort>/mesh/relay

    // Accept inbound mesh messages via HTTP (signed, verified)
    app.post('/mesh/relay', writeLimiter, (req, res) => {
      // Handle relay registration (action: 'register') through the same endpoint
      // so it works through the PHP bridge which only proxies POST /mesh/relay
      if (req.body.action === 'register') {
        const { nodeId, networkName, publicKey, capabilities, signature, timestamp } = req.body;
        if (!nodeId || !networkName) {
          return res.status(400).json({ error: 'nodeId and networkName required for register' });
        }

        // Timestamp is REQUIRED for replay protection — reject if missing or stale
        if (!timestamp || typeof timestamp !== 'number') {
          return res.status(400).json({ error: 'timestamp required for registration (replay protection)' });
        }
        if (Math.abs(aguwa.now() - timestamp) > 300000) {
          return res.status(403).json({ error: 'Registration timestamp too old (replay protection)' });
        }

        // Verify ML-DSA-65 registration signature — no unsigned registrations
        if (!signature || !publicKey) {
          return res.status(403).json({ error: 'Signed registration required (signature + publicKey)' });
        }

        // SECURITY: For FIRST registration, we must trust the supplied publicKey
        // since the peer is unknown. On subsequent registrations, verify against
        // the STORED key to prevent identity takeover.
        const knownKey = this._resolvePeerPublicKey(nodeId);
        const verifyKey = knownKey || publicKey;  // Trust first contact, verify thereafter

        try {
          const sigData = JSON.stringify({ action: 'register', nodeId, networkName, timestamp });
          const valid = this.identity.verify(sigData, signature, verifyKey);
          if (!valid) {
            return res.status(403).json({ error: 'Invalid registration signature' });
          }
        } catch {
          return res.status(403).json({ error: 'Registration signature verification failed' });
        }

        // If we had a stored key and the supplied key differs, reject (identity conflict)
        if (knownKey && publicKey !== knownKey) {
          return res.status(403).json({ error: 'Public key mismatch — identity conflict' });
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
        this._relayClients.set(nodeId, aguwa.now());

        log.info(`HTTP relay peer registered (verified): ${peerTag(nodeId)}`);
        log.info(`  ⚠ Relay peers use HTTP polling (30s cadence) — reduced throughput & latency vs WebSocket`);
        log.info(`  ⚠ Relay is a firewall-traversal fallback, not the intended full-duplex mesh connection`);
        return res.json({
          success: true,
          nodeId: this.identity.identity.nodeId,
          publicKey: this.identity.identity.publicKey,
        });
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

      // Require ML-DSA-65 batch signature — verified against KNOWN peer key
      if (!signature) {
        return res.status(403).json({ error: 'Signed relay batch required' });
      }

      // SECURITY: Look up the sender's STORED public key from our registry.
      // Never verify against an attacker-supplied publicKey in the body.
      const knownBatchKey = this._resolvePeerPublicKey(senderNodeId);
      if (!knownBatchKey) {
        return res.status(403).json({ error: 'Unknown relay peer — register first' });
      }
      try {
        const sigData = JSON.stringify({ messages, senderNodeId });
        const valid = this.identity.verify(sigData, signature, knownBatchKey);
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
              this.mesh.annex._handleAnnexMessage(msg.annex, senderNodeId).catch(() => { });
            }
            accepted++;
          } catch {
            // Skip malformed messages
          }
        }
      }

      // Refresh relay client last-seen on poll
      if (this._relayClients && this._relayClients.has(senderNodeId)) {
        this._relayClients.set(senderNodeId, aguwa.now());
      }

      // Return our own pending outbound messages for this sender (bi-directional relay)
      const outbound = this._drainRelayOutbox(senderNodeId);

      res.json({
        accepted,
        outbound,
        nodeId: this.identity.identity.nodeId,
        publicKey: this.identity.identity.publicKey,
        timestamp: aguwa.now(),
      });
    });

    // Retrieve pending relay messages for a specific node (pull-based)
    app.get('/mesh/relay/:nodeId', (req, res) => {
      const outbound = this._drainRelayOutbox(req.params.nodeId);
      res.json({
        messages: outbound,
        nodeId: this.identity.identity.nodeId,
        timestamp: aguwa.now(),
      });
    });

    // Register as an HTTP-relay peer (for nodes that can't do WS)
    // SECURITY: Requires peer auth — prevents phantom peer registration
    app.post('/mesh/relay/register', writeLimiter, requirePeerAuth, (req, res) => {
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

      log.info(`HTTP relay peer registered: ${peerTag(nodeId)} via ${relayEndpoint}`);
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

    // Connect to a peer via HTTP relay (firewall traversal fallback)
    app.post('/connect/relay', writeLimiter, requirePeerAuth, async (req, res) => {
      const { relayEndpoint, nodeId } = req.body;

      if (!relayEndpoint || typeof relayEndpoint !== 'string') {
        return res.status(400).json({ error: 'relayEndpoint URL required (e.g. https://yakmesh.dev/mesh/relay.php)' });
      }

      // nodeId is optional — we'll learn it from the registration response
      const candidate = {
        nodeId: nodeId || `relay-${aguwa.now()}`,
        relayEndpoint,
      };

      try {
        await this._registerWithRelay(candidate);
        const relayPollCount = this._relayPollers?.size || 0;
        const relayClientCount = this._relayClients?.size || 0;
        res.json({
          success: true,
          message: `Relay connection established to ${relayEndpoint}`,
          relayPeers: relayPollCount + relayClientCount,
          totalPeers: this.mesh.getPeers().length + relayPollCount + relayClientCount,
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
      const rowId = data.id || aguwa.now();
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

    // ═══════════════════════════════════════════════════════════════════
    // SERVER DIRECTORY — C2C Lighthouse (public server browser)
    // ═══════════════════════════════════════════════════════════════════

    // List all servers (public — no auth required)
    app.get('/servers', (req, res) => {
      if (!this.serverDirectory) {
        return res.status(503).json({ error: 'Server directory not initialized' });
      }
      const status = req.query.status || null;
      const limit = parseInt(req.query.limit) || 100;
      const directory = this.serverDirectory.getDirectory({ status, limit });
      const stats = this.serverDirectory.getStats();
      res.json({ servers: directory, stats, serverTime: aguwa.now() });
    });

    // Single server detail
    app.get('/servers/:nodeId', (req, res) => {
      if (!this.serverDirectory) {
        return res.status(503).json({ error: 'Server directory not initialized' });
      }
      const server = this.serverDirectory.getServer(req.params.nodeId);
      if (!server) {
        return res.status(404).json({ error: 'Server not found' });
      }
      res.json({ server });
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
      res.json({ rumors, serverTime: aguwa.now() });
    });

    // SSE endpoint: real-time push of rumors (replaces polling for MeshBridge)
    // GET /rumors/subscribe?topic=<optional> — Server-Sent Events stream
    // SECURITY: Restricted to localhost (mesh topology leaks if exposed)
    app.get('/rumors/subscribe', (req, res) => {
      // Only allow connections from localhost — SSE is for local MeshBridge, not remote clients
      const remoteAddr = req.socket?.remoteAddress || '';
      const isLocal = remoteAddr === '127.0.0.1' || remoteAddr === '::1' || remoteAddr === '::ffff:127.0.0.1';
      if (!isLocal) {
        return res.status(403).json({ error: 'SSE subscribe restricted to localhost' });
      }

      const topicFilter = req.query.topic || null;

      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',  // Disable nginx buffering
      });
      res.write('retry: 5000\n\n');  // Auto-reconnect after 5s

      // Listener that forwards matching rumors (origin stripped to prevent topology leak)
      const onRumor = (topic, data, _origin) => {
        if (topicFilter && topic !== topicFilter) return;
        const event = JSON.stringify({ topic, data, timestamp: aguwa.now() });
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

    // =========================================
    // Identity Backup / Recovery (localhost-only)
    // =========================================

    // Export mnemonic backup (CRITICAL — localhost-only, never expose to network)
    app.post('/identity/backup', writeLimiter, (req, res) => {
      const remoteAddr = req.socket?.remoteAddress || '';
      const isLocal = remoteAddr === '127.0.0.1' || remoteAddr === '::1' || remoteAddr === '::ffff:127.0.0.1';
      if (!isLocal) {
        return res.status(403).json({ error: 'Identity backup restricted to localhost' });
      }

      if (!this.identity?.machineSeed) {
        return res.status(503).json({ error: 'Identity not initialized' });
      }

      try {
        const { password } = req.body || {};
        const result = this.identity.machineSeed.exportMnemonic(password || undefined);
        res.json({
          words: result.words,
          encrypted: result.encrypted || null,
          persistentId: this.identity.machineSeed.getPersistentId(),
          wordCount: result.words.length,
          warning: 'WRITE THESE WORDS DOWN OFFLINE. This is the ONLY way to recover your identity on new hardware.',
        });
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    });

    // Verify mnemonic matches current seed (localhost-only)
    app.post('/identity/verify-mnemonic', writeLimiter, (req, res) => {
      const remoteAddr = req.socket?.remoteAddress || '';
      const isLocal = remoteAddr === '127.0.0.1' || remoteAddr === '::1' || remoteAddr === '::ffff:127.0.0.1';
      if (!isLocal) {
        return res.status(403).json({ error: 'Identity verification restricted to localhost' });
      }

      if (!this.identity?.machineSeed) {
        return res.status(503).json({ error: 'Identity not initialized' });
      }

      try {
        const { words } = req.body || {};
        if (!Array.isArray(words) || words.length !== 33) {
          return res.status(400).json({ error: 'Must provide array of 33 mnemonic words' });
        }
        const result = this.identity.machineSeed.verifyMnemonic(words);
        res.json(result);
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    });

    // Restore identity from mnemonic on new hardware (localhost-only, destructive)
    app.post('/identity/restore', writeLimiter, async (req, res) => {
      const remoteAddr = req.socket?.remoteAddress || '';
      const isLocal = remoteAddr === '127.0.0.1' || remoteAddr === '::1' || remoteAddr === '::ffff:127.0.0.1';
      if (!isLocal) {
        return res.status(403).json({ error: 'Identity restore restricted to localhost' });
      }

      try {
        const { words, encrypted, password } = req.body || {};

        let mnemonicWords = words;

        // If encrypted blob provided, decrypt first
        if (encrypted && password) {
          const MachineSeed = (await import('../identity/machine-seed.js')).default;
          mnemonicWords = MachineSeed.decryptMnemonic(encrypted, password);
        }

        if (!Array.isArray(mnemonicWords) || mnemonicWords.length !== 33) {
          return res.status(400).json({ error: 'Must provide 33 mnemonic words (or encrypted blob + password)' });
        }

        const MachineSeed = (await import('../identity/machine-seed.js')).default;
        const dataDir = this.config?.node?.dataDir || './data';
        const restored = MachineSeed.importFromMnemonic(mnemonicWords, dataDir);

        res.json({
          success: true,
          persistentId: restored.getPersistentId(),
          message: 'Identity restored. Restart the node to use the new identity.',
        });
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    });

    // =========================================
    // Anti-Cheat: Signing API (localhost-only, Tier 3 fallback)
    // =========================================
    // C2C and yakapp can request ML-DSA-65 signatures via HTTP when the
    // named pipe isn't available. Localhost-only to prevent remote abuse.

    app.post('/sign', writeLimiter, (req, res) => {
      const remoteAddr = req.socket?.remoteAddress || '';
      const isLocal = remoteAddr === '127.0.0.1' || remoteAddr === '::1' || remoteAddr === '::ffff:127.0.0.1';
      if (!isLocal) {
        return res.status(403).json({ error: 'Signing restricted to localhost' });
      }

      if (!this.identity?.identity) {
        return res.status(503).json({ error: 'Identity not initialized' });
      }

      const { message } = req.body;
      if (!message || typeof message !== 'string') {
        return res.status(400).json({ error: 'message (string) required' });
      }
      if (message.length > 65536) {
        return res.status(400).json({ error: 'message too large (max 64KB)' });
      }

      try {
        const signature = this.identity.sign(message);
        res.json({
          signature,
          publicKey: this.identity.identity.publicKey,
          persistentId: this.identity.identity.persistentId || null,
          algorithm: 'ML-DSA-65',
        });
      } catch (e) {
        res.status(500).json({ error: `Signing failed: ${e.message}` });
      }
    });

    // Verify a signature (public — anyone can verify, only localhost can sign)
    app.post('/sign/verify', (req, res) => {
      const { message, signature, publicKey } = req.body;
      if (!message || !signature || !publicKey) {
        return res.status(400).json({ error: 'message, signature, and publicKey required' });
      }

      try {
        const valid = this.identity.verify(message, signature, publicKey);
        res.json({ valid, algorithm: 'ML-DSA-65' });
      } catch (e) {
        res.json({ valid: false, error: e.message });
      }
    });

    // Get handshake payload (for peer connection)
    app.get('/network/handshake', (req, res) => {
      if (!this.genesisNetwork) {
        return res.status(503).json({ error: 'Genesis network not initialized' });
      }

      res.json(this.genesisNetwork.createHandshake());
    });

    // Verify a peer's handshake
    // SECURITY: Input validation + peer auth
    app.post('/network/verify', writeLimiter, requirePeerAuth, (req, res) => {
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
    // SECURITY: Rate limited + peer auth + input validation
    app.post('/oracle/challenge', writeLimiter, requirePeerAuth, (req, res) => {
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
        message: `Challenge sent to peer ${peerTag(peerId)}`
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
    // SECURITY: Rate limited + peer auth + input validation + hash obfuscation
    app.post('/oracle/submit', writeLimiter, requirePeerAuth, async (req, res) => {
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
          timestamp: aguwa.now(),
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
    // SECURITY: Peer auth required — admin action
    app.post('/oracle/resolve', writeLimiter, requirePeerAuth, (req, res) => {
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
      const startTime = this._startTime || aguwa.now();
      const uptime = Math.floor((aguwa.now() - startTime) / 1000);

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
          routingSecurity: '256-bit (162T)',
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
        // Count unique websites by domain (not replicated manifests)
        const uniqueSites = this.websiteAdapter.domains.size || 1; // At least our own site
        websiteInfo = {
          status: 'active',
          websites: this.websiteAdapter.manifests.size,  // Total manifests (replicas from all nodes)
          uniqueSites,                                    // Actual unique sites by domain
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

      const status = this.timeSource.getStatus();
      status.aguwa = aguwa.getStatus();
      res.json(status);
    });

    // AGUWA Kuramoto oscillator status + Sybil defense
    app.get('/time/aguwa', (req, res) => {
      const status = aguwa.getStatus();
      const divergent = aguwa.detectDivergentPeers();
      res.json({ ...status, divergentPeers: divergent });
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
    // Public Time API — GPS Time for the World
    // =========================================
    // These endpoints serve live GPS time from the MA-902 grandmaster clock.
    // On the LAN node: data comes directly from SNMP. On meshed Hostinger node:
    // data arrives via mesh peering with the LAN grandmaster.
    // The landing page at yakmesh.dev/time/ polls these endpoints.

    app.get('/api/time', (req, res) => {
      const now = aguwa.now();
      const status = this.timeSource?.getStatus() || {};
      const sats = status.satellites || status.ma902?.satellites || {};
      const locked = status.trustLevel === 'gps' || status.trustLevel === 'atomic';

      // Mesh grandmaster reference (received via time:heartbeat gossip)
      const meshRef = this.meshTimeReference;
      const hasMeshGrandmaster = meshRef && meshRef.lock && (aguwa.now() - meshRef.receivedAt < 120_000);

      // Effective source: local GPS if available, else mesh grandmaster, else system
      const effectiveStratum = locked ? 1 : (hasMeshGrandmaster ? meshRef.stratum : 2);
      const effectiveSource = locked ? 'MA-902/S-C1 GPS' :
        (hasMeshGrandmaster ? `mesh/${meshRef.nodeName || peerTag(meshRef.fromNodeId)}` : 'system');
      const effectiveAccuracy = locked ? 1 : (hasMeshGrandmaster ? (meshRef.accuracy_ms ?? 5) : 50);
      const effectiveQuality = locked ? 'excellent' : (hasMeshGrandmaster ? 'mesh-synced' : 'degraded');
      const effectiveLock = locked || (hasMeshGrandmaster && meshRef.lock);

      res.set({
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'X-Yakmesh-Time': (now / 1000).toFixed(3),
        'X-Yakmesh-Stratum': String(effectiveStratum),
        'X-Yakmesh-Source': effectiveSource,
      });

      const body = {
        iso: new Date(now).toISOString(),
        unix: now / 1000,
        unix_ms: now,
        stratum: effectiveStratum,
        source: effectiveSource,
        accuracy_ms: effectiveAccuracy,
        leap_indicator: 0,
        satellites: {
          visible: locked ? (sats.visible ?? 0) : (hasMeshGrandmaster ? (meshRef.satellites?.visible ?? 0) : 0),
          used: locked ? (sats.used ?? 0) : (hasMeshGrandmaster ? (meshRef.satellites?.used ?? 0) : 0),
          tracking: locked ? (sats.tracking ?? 0) : (hasMeshGrandmaster ? (meshRef.satellites?.tracking ?? 0) : 0),
          constellations: locked ? (sats.constellations ?? []) : (hasMeshGrandmaster ? (meshRef.satellites?.constellations ?? []) : []),
        },
        lock: effectiveLock,
        quality: effectiveQuality,
        offset_ns: status.offset ?? 0,
        reference_id: locked ? 'GPS' : (hasMeshGrandmaster ? 'MESH' : 'SYS'),
        // Public NTP server (always available — points to MA-902 grandmaster)
        public_ntp: 'time.yakmesh.dev',
      };

      // If this node isn't GPS-backed but has a mesh grandmaster, include its data
      if (!locked && hasMeshGrandmaster) {
        body.mesh_grandmaster = {
          nodeId: meshRef.fromNodeId,
          nodeName: meshRef.nodeName,
          stratum: meshRef.stratum,
          lock: meshRef.lock,
          satellites: meshRef.satellites,
          ma902: meshRef.ma902 || null,
          trustLevel: meshRef.trustLevel,
          publicNtp: meshRef.publicNtp,
          age_ms: aguwa.now() - meshRef.receivedAt,
        };
      }

      res.json(body);
    });

    app.get('/api/mesh-health', (req, res) => {
      res.set({ 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' });
      res.json(aguwa.getStatus());
    });

    app.get('/api/time/simple', (req, res) => {
      const now = aguwa.now();
      const status = this.timeSource?.getStatus() || {};
      const locked = status.trustLevel === 'gps' || status.trustLevel === 'atomic';
      const meshRef = this.meshTimeReference;
      const hasMeshGM = meshRef && meshRef.lock && (aguwa.now() - meshRef.receivedAt < 120_000);
      const eff = locked ? 1 : (hasMeshGM ? meshRef.stratum : 2);
      const q = locked ? 'excellent' : (hasMeshGM ? 'mesh-synced' : 'degraded');
      res.set({ 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' });
      res.json({ t: now, s: eff, q, ntp: 'time.yakmesh.dev' });
    });

    app.get('/api/health', (req, res) => {
      const status = this.timeSource?.getStatus() || {};
      const sats = status.satellites || status.ma902?.satellites || {};
      const locked = status.trustLevel === 'gps' || status.trustLevel === 'atomic';
      const meshRef = this.meshTimeReference;
      const hasMeshGM = meshRef && meshRef.lock && (aguwa.now() - meshRef.receivedAt < 120_000);
      const effectiveStatus = locked ? 'healthy' : (hasMeshGM ? 'mesh-synced' : 'degraded');

      res.set({ 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' });
      res.json({
        status: effectiveStatus,
        lock: locked,
        satellites_visible: sats.visible ?? 0,
        satellites_used: sats.used ?? 0,
        constellations: sats.constellations ?? [],
        alarm: status.alarm ?? false,
        quality: locked ? 'excellent' : (hasMeshGM ? 'mesh-synced' : 'degraded'),
        trust_level: status.trustLevel ?? 'unknown',
        mesh_grandmaster: hasMeshGM ? {
          nodeName: meshRef.nodeName,
          stratum: meshRef.stratum,
          lock: meshRef.lock,
          satellites_used: meshRef.satellites?.used ?? 0,
          publicNtp: meshRef.publicNtp,
          age_ms: aguwa.now() - meshRef.receivedAt,
        } : null,
        public_ntp: 'time.yakmesh.dev',
      });
    });

    // =========================================
    // SANGHA Collective Status (v3.0)
    // =========================================

    // Get SANGHA collective status
    app.get('/api/sangha', (req, res) => {
      if (!this.sangha) {
        return res.status(503).json({ error: 'SANGHA not initialized' });
      }
      res.set({ 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' });
      res.json(this.sangha.getStatus());
    });

    // Get recent antibody circulations
    app.get('/api/sangha/circulations', (req, res) => {
      if (!this.sangha) {
        return res.status(503).json({ error: 'SANGHA not initialized' });
      }
      const count = Math.min(parseInt(req.query.count) || 10, 100);
      res.set({ 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' });
      res.json({
        circulations: this.sangha.getRecentCirculations(count),
        status: this.sangha.getStatus(),
      });
    });

    // Trigger manual circulation (for testing)
    app.post('/api/sangha/circulate', async (req, res) => {
      if (!this.sangha) {
        return res.status(503).json({ error: 'SANGHA not initialized' });
      }
      try {
        const result = await this.sangha.circulate();
        res.json({ success: true, result });
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
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
    // SECURITY: Peer auth — only known peers can trigger gate verification
    app.post('/security/namche/verify/:gate', writeLimiter, requirePeerAuth, (req, res) => {
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
    // SECURITY: Peer auth — only known peers can request identity verification
    app.post('/security/doko/verify', writeLimiter, requirePeerAuth, (req, res) => {
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
      this._ensureGeoProofService();

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
      this._ensureGeoProofService();

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
          name: lm.name || `Landmark ${peerTag(lm.nodeId)}`,
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
    // SECURITY: Peer auth — prevent phantom landmark injection
    app.post('/geo/landmarks', writeLimiter, requirePeerAuth, (req, res) => {
      const { name, lat, lon, nodeId, endpoint } = req.body;

      if (typeof lat !== 'number' || typeof lon !== 'number') {
        return res.status(400).json({ error: 'lat and lon must be numbers' });
      }
      if (lat < -90 || lat > 90 || lon < -180 || lon > 180) {
        return res.status(400).json({ error: 'Invalid coordinates' });
      }

      // Initialize geo proof service lazily if needed
      this._ensureGeoProofService();

      const service = this.geoProofService;
      if (!service) {
        return res.status(503).json({ error: 'Geographic proof service not initialized' });
      }

      const landmarkId = nodeId || `landmark-${aguwa.now()}`;
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
    // SECURITY: Peer auth required for proof generation
    app.post('/geo/prove', writeLimiter, requirePeerAuth, async (req, res) => {
      const { force } = req.body || {};

      // Initialize geo proof service lazily if needed
      this._ensureGeoProofService();

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
            measuredAt: aguwa.now(),
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
                landmarkName: lm?.name || peerTag(z.landmarkId),
                radiusKm: z.minDistanceKm,
              };
            }),
          },
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // Verify another node's geographic claims using PRAMAAN physics
    // Accepts either a nodeId (lookup cached proof) or a full proof payload
    app.post('/geo/verify', writeLimiter, async (req, res) => {
      const { nodeId, proof: proofData } = req.body;

      if (!nodeId && !proofData) {
        return res.status(400).json({ error: 'nodeId or proof required' });
      }

      if (!this.geoProofService) {
        return res.status(503).json({
          verified: false,
          reason: 'Geographic proof service not initialized'
        });
      }

      try {
        // Deserialize the peer's proof
        let peerProof;
        if (proofData) {
          // Direct proof submission — deserialize and verify
          peerProof = GeographicProof.deserialize(proofData);
        } else {
          // Look up cached proof from gossip
          peerProof = this.geoProofService.proofs.get(nodeId);
          if (!peerProof) {
            return res.json({
              verified: false,
              nodeId,
              reason: 'No geo-proof available for this node. Request via gossip first.',
              confidence: 0,
            });
          }
        }

        // ── PRAMAAN Verification: Physics-based consistency checks ──
        const verificationResults = [];
        let sharedLandmarks = 0;
        let physicsViolations = 0;
        const ourMeasurements = this.geoProofService.measurementCache;

        for (const zone of peerProof.exclusionZones) {
          const result = {
            landmarkId: zone.landmarkId,
            landmarkName: zone.landmarkName,
            claimedRttMs: zone.rttMs,
            claimedMinDistanceKm: zone.minDistanceKm,
            valid: true,
            checks: [],
          };

          // Check 1: RTT must be positive and physically plausible
          if (zone.rttMs == null || zone.rttMs <= 0) {
            result.valid = false;
            result.checks.push('FAIL: RTT must be positive');
            physicsViolations++;
          } else {
            result.checks.push('PASS: RTT positive');
          }

          // Check 2: Claimed distance must equal calculateMinDistance(rtt) within precision
          if (zone.rttMs > 0) {
            const expectedMinDist = calculateMinDistance(zone.rttMs, 'fiber');
            const tolerance = zone.precisionKm || 50; // precision from time source
            if (Math.abs(zone.minDistanceKm - expectedMinDist) > tolerance) {
              result.valid = false;
              result.checks.push(
                `FAIL: Distance ${zone.minDistanceKm.toFixed(1)}km inconsistent with RTT ${zone.rttMs.toFixed(1)}ms (expected ~${expectedMinDist.toFixed(1)}km)`
              );
              physicsViolations++;
            } else {
              result.checks.push('PASS: Distance consistent with RTT (speed-of-light)');
            }
          }

          // Check 3: Cross-reference with OUR measurements to the same landmark
          const ourMeasurement = ourMeasurements.get(zone.landmarkId);
          if (ourMeasurement) {
            sharedLandmarks++;
            const ourRtt = ourMeasurement.getMinRTT();
            if (ourRtt !== null) {
              // Triangle inequality: |peerRTT - ourRTT| should be <= sum
              // (both should be positive, and wildly different RTTs to the same
              //  landmark are suspicious but not impossible — different continents)
              result.checks.push(
                `INFO: Our RTT to ${zone.landmarkName}: ${ourRtt.toFixed(1)}ms vs peer ${zone.rttMs?.toFixed(1)}ms`
              );
              result.ourRttMs = ourRtt;
            }
          }

          verificationResults.push(result);
        }

        // Compute overall confidence
        const totalZones = peerProof.exclusionZones.length;
        const validZones = verificationResults.filter(r => r.valid).length;
        const confidence = totalZones > 0 ? validZones / totalZones : 0;
        const verified = physicsViolations === 0 && totalZones >= GEO_PROOF_CONFIG.minLandmarks;

        res.json({
          verified,
          nodeId: peerProof.nodeId || nodeId,
          dokoId: peerProof.dokoId,
          validZones,
          totalZones,
          sharedLandmarks,
          physicsViolations,
          confidence,
          timeSource: peerProof.timeSource,
          proofTimestamp: peerProof.timestamp,
          zones: verificationResults,
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

        // Handle TCP-level client errors (ECONNRESET, EPIPE, etc.)
        // These occur when clients disconnect abruptly — normal in P2P mesh.
        // Without this handler, they bubble up as uncaught exceptions.
        server.on('clientError', (err, socket) => {
          if (socket.writable) {
            socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
          }
          socket.destroy();
        });

        resolve();
      });
      server.on('error', reject);
    });
  }

  /**
   * Auto-register with relay peers from YAKMESH_RELAY_PEERS config.
   * Non-blocking — runs after server is up, fire-and-forget like bootstrap.
   */
  _connectToRelayPeers() {
    const relayPeers = this.config.relayPeers || [];
    if (relayPeers.length === 0) return;

    log.info(`RELAY: ${relayPeers.length} relay peer(s) from config — registering in background`);

    // Delay slightly to let identity and mesh fully initialize
    setTimeout(async () => {
      for (const endpoint of relayPeers) {
        if (!endpoint || typeof endpoint !== 'string' || !endpoint.startsWith('http')) {
          log.warn(`RELAY: skipping invalid endpoint: ${endpoint}`);
          continue;
        }

        const candidate = {
          nodeId: `relay-${aguwa.now()}`,
          relayEndpoint: endpoint,
        };

        try {
          await this._registerWithRelay(candidate);
          log.info(`RELAY: ✓ registered with ${endpoint}`);
        } catch (err) {
          log.warn(`RELAY: ${endpoint} registration failed — ${err.message}`);
          // Retry after 30s (once) — relay peers may not be up yet
          setTimeout(async () => {
            try {
              await this._registerWithRelay(candidate);
              log.info(`RELAY: ✓ registered with ${endpoint} (retry)`);
            } catch (e) {
              log.warn(`RELAY: ${endpoint} retry failed — ${e.message}`);
            }
          }, 30000);
        }
      }
    }, 3000);
  }

  /**
   * Get active relay info for gossip propagation.
   * Returns list of relay endpoints this node is registered with,
   * so peers can discover relay paths through HELLO broadcasts.
   */
  _getActiveRelayInfo() {
    const endpoints = [];
    if (this._relayPollers) {
      for (const [nodeId, _interval] of this._relayPollers) {
        // Find the relay endpoint URL for this poller
        // We track candidates when we register — check _relayEndpoints map
        if (this._relayEndpoints?.has(nodeId)) {
          endpoints.push(this._relayEndpoints.get(nodeId));
        }
      }
    }
    return { relayEndpoints: endpoints };
  }

  /**
   * Bootstrap — SEED ONLY mechanism for initial network join.
   *
   * Connection priority (proper flow):
   *   1. DirectWS — known peers from gossip, saved state, inbound connections
   *   2. Bootstrap — initial network discovery when no peers exist
   *   3. Beacon Relays — NAT traversal fallback
   *   4. Crawlers — active network discovery
   *   5. Gossip — passive peer exchange (MANTRA)
   *
   * Bootstrap ONLY activates when we have zero peers. Once connected to the
   * network, we rely on gossip for peer exchange. This prevents duplicate
   * connections and race conditions.
   */
  _connectToBootstrap() {
    // ── Build bootstrap peer list once at startup ──
    if (!this._bootstrapPeers) {
      this._buildBootstrapPeerList();
    }

    if (this._bootstrapPeers.length === 0) {
      log.info('BOOTSTRAP: no remote peers configured');
      return;
    }

    // ── Check if we actually need bootstrap (zero peers) ──
    const currentPeers = this.mesh?.getPeers?.() || [];
    if (currentPeers.length > 0) {
      log.debug(`BOOTSTRAP: skipping — already have ${currentPeers.length} peer(s), using gossip for discovery`);
      return;
    }

    log.info(`BOOTSTRAP: no peers — seeding network from ${this._bootstrapPeers.length} configured peer(s)`);

    // ── Try all bootstrap peers concurrently ──
    this._tryBootstrapConnections();

    // ── Setup recovery watcher (only runs when we lose all peers) ──
    if (!this._bootstrapRecoverySetup) {
      this._bootstrapRecoverySetup = true;
      this.mesh.on('peer:disconnected', () => {
        // Check if we lost ALL peers — if so, trigger bootstrap
        setTimeout(() => {
          const peers = this.mesh?.getPeers?.() || [];
          if (peers.length === 0) {
            log.info('BOOTSTRAP: lost all peers — re-seeding network');
            this._tryBootstrapConnections();
          }
        }, 2000); // Small delay to allow reconnects
      });
    }
  }

  /**
   * Build the filtered list of bootstrap peers (run once at startup).
   */
  _buildBootstrapPeerList() {
    const localAddrs = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);
    const ifaces = networkInterfaces();
    for (const addrs of Object.values(ifaces)) {
      for (const addr of addrs) localAddrs.add(addr.address);
    }
    const ourWsPort = this.mesh.boundPort || this.config.network.wsPort;

    this._bootstrapPeers = [];
    for (const endpoint of this.config.bootstrap) {
      let url;
      try { url = new URL(endpoint); } catch {
        log.warn(`BOOTSTRAP: invalid endpoint: ${endpoint}`);
        continue;
      }
      const epPort = parseInt(url.port, 10);
      if (epPort === ourWsPort && localAddrs.has(url.hostname)) {
        log.debug(`BOOTSTRAP: skipping self: ${endpoint}`);
        continue;
      }
      this._bootstrapPeers.push({
        endpoint,
        failures: 0,
        lastTry: 0,
      });
    }

    if (this._bootstrapPeers.length > 0) {
      log.info(`BOOTSTRAP: ${this._bootstrapPeers.length} seed peer(s) configured`);
    }
  }

  /**
   * Attempt to connect to bootstrap peers for initial network seeding.
   * Only called when we have zero peers (not as a maintenance loop).
   */
  _tryBootstrapConnections() {
    if (!this._bootstrapPeers) return;

    // Double-check we still need to seed (another peer might have connected)
    const currentPeers = this.mesh?.getPeers?.() || [];
    if (currentPeers.length > 0) {
      log.debug('BOOTSTRAP: peer connected during seeding, stopping');
      return;
    }

    for (const peer of this._bootstrapPeers) {
      // Simple backoff: 5s minimum between attempts to same peer
      if (aguwa.now() - peer.lastTry < 5000) continue;
      peer.lastTry = aguwa.now();

      // Fire-and-forget with 5s timeout
      this._connectWithTimeout(peer.endpoint, 5_000)
        .then(() => {
          log.info(`BOOTSTRAP: ✓ seeded from ${peer.endpoint}`);
          peer.failures = 0;
        })
        .catch(() => {
          peer.failures++;
          log.debug(`BOOTSTRAP: ${peer.endpoint} unreachable (attempt ${peer.failures})`);
        });
    }
  }

  /**
   * Connect to a peer with an explicit timeout.
   * Rejects if the connection hasn't completed within `ms` milliseconds,
   * instead of waiting for the OS TCP timeout (21-30s on Windows).
   */
  _connectWithTimeout(endpoint, ms) {
    return new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          reject(new Error(`timeout after ${ms}ms`));
        }
      }, ms);

      this.mesh.connect(endpoint)
        .then((result) => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            resolve(result);
          }
        })
        .catch((err) => {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            reject(err);
          }
        });
    });
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
      // Pass nodeId for MITM detection in WELCOME handler
      if (candidate.wsEndpoint) {
        try {
          log.info(`SHERPA auto-connect WS → ${candidate.wsEndpoint} (${peerTag(candidate.nodeId)})`);
          await this.mesh.connect(candidate.wsEndpoint, candidate.nodeId);
          this.sherpa.markConnected(candidate.nodeId);
          log.info(`SHERPA auto-connect ✓ ${peerTag(candidate.nodeId)} via WS`);
          continue;  // Success — no need for relay fallback
        } catch (e) {
          log.debug(`SHERPA WS failed: ${candidate.wsEndpoint} — ${e.message}`);
        }
      }

      // Fall back to HTTP relay (half-duplex, firewall traversal)
      if (candidate.relayEndpoint) {
        try {
          log.info(`SHERPA relay register → ${candidate.relayEndpoint} (${peerTag(candidate.nodeId)})`);
          await this._registerWithRelay(candidate);
          log.info(`SHERPA relay registered ✓ ${peerTag(candidate.nodeId)}`);
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
      timestamp: aguwa.now(),
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

    // Learn the remote node's actual nodeId from the registration response
    const regResult = await resp.json();
    if (regResult.nodeId && candidate.nodeId.startsWith('relay-')) {
      candidate.nodeId = regResult.nodeId;
    }

    // Store remote node's public key for signature verification (gossip, ANNEX)
    // Without this, relay-only peers can't verify each other's rumor signatures
    if (regResult.publicKey && regResult.nodeId) {
      if (!this.mesh._relayPeerKeys) this.mesh._relayPeerKeys = new Map();
      this.mesh._relayPeerKeys.set(regResult.nodeId, regResult.publicKey);
      if (this.sherpa) {
        this.sherpa.registry.upsert({
          nodeId: regResult.nodeId,
          publicKey: regResult.publicKey,
          capabilities: { httpRelay: true },
        });
      }
    }

    // Start polling for inbound messages if not already polling
    if (!this._relayPollers) this._relayPollers = new Map();
    if (!this._relayEndpoints) this._relayEndpoints = new Map();

    if (!this._relayPollers.has(candidate.nodeId)) {
      const pollInterval = setInterval(async () => {
        try {
          await this._pollRelay(candidate);
        } catch (e) {
          log.debug(`Relay poll error ${peerTag(candidate.nodeId)}: ${e.message}`);
        }
      }, 30000);  // Poll every 30 seconds

      this._relayPollers.set(candidate.nodeId, pollInterval);
      this._relayEndpoints.set(candidate.nodeId, relayUrl);
      this.sherpa.markConnected(candidate.nodeId);
      log.warn(`Relay peer ${peerTag(candidate.nodeId)} connected via HTTP polling (30s cadence)`);
      log.warn(`  ⚠ Relay connections have reduced throughput & higher latency vs direct WebSocket`);
      log.warn(`  ⚠ This is a firewall-traversal fallback — useful for emergency mesh connectivity`);
      log.warn(`  ⚠ Gossip propagation, ANNEX encryption, and consensus still function but may lag`);

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

    // Learn/refresh remote node's public key from poll response
    // Ensures relay-only peers can verify each other's gossip signatures
    if (data.publicKey && data.nodeId) {
      if (!this.mesh._relayPeerKeys) this.mesh._relayPeerKeys = new Map();
      this.mesh._relayPeerKeys.set(data.nodeId, data.publicKey);
    }

    // Process inbound messages from relay
    if (data.outbound && Array.isArray(data.outbound)) {
      for (const msg of data.outbound) {
        try {
          // Dispatch by msg.type (e.g., 'gossip', 'hello') — not 'message'
          if (msg && msg.type) {
            this.mesh.emit(msg.type, msg, null, candidate.nodeId);
            // Route ANNEX messages arriving via relay
            if (msg.annex && this.mesh.annex) {
              this.mesh.annex._handleAnnexMessage(msg.annex, candidate.nodeId).catch(() => { });
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

    queue.push({ ...message, _relayTs: aguwa.now() });

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
   * Initialize YakAI Adapter — bridges yakai with ComputeScheduler + identity
   * Follows the same pattern as _initWebsiteAdapter.
   */
  async _initYakaiAdapter() {
    try {
      const { YakaiAdapter, createYakaiEndpoints } = await import('../adapters/adapter-yakai/index.js');

      this.yakaiAdapter = new YakaiAdapter(this, {
        yakaiPort: parseInt(process.env.YAKAI_PORT || '3092', 10),
        maxConcurrentInference: parseInt(process.env.YAKAI_MAX_INFERENCE || '4', 10),
      });

      await this.yakaiAdapter.init();

      // Mount yakai bridge endpoints on yakmesh HTTP server
      if (this.app && createYakaiEndpoints) {
        createYakaiEndpoints(this.app, this.yakaiAdapter);
      }

      log.info('✓ YakAI Adapter enabled');
      log.info(`  Bridge: /yakai/capabilities, /yakai/identity, /yakai/sign, /yakai/stats`);
    } catch (error) {
      // YakAI adapter is optional — yakai still works with Gemini API fallback
      if (error.code !== 'ERR_MODULE_NOT_FOUND') {
        log.warn('⚠️ YakAI Adapter:', { error: error.message });
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
  const args = process.argv.slice(2);

  // ── CLI: yakmesh identity backup ──
  if (args[0] === 'identity' && args[1] === 'backup') {
    const MachineSeed = (await import('../identity/machine-seed.js')).default;
    const config = await loadConfig();
    const dataDir = config.node?.dataDir || './data';
    const ms = new MachineSeed(dataDir);
    await ms.init();

    const password = args[2] || undefined; // optional password as 3rd arg
    const result = ms.exportMnemonic(password);

    console.log('\n╔═══════════════════════════════════════════════════════════════╗');
    console.log('║          🦬 YAKMESH IDENTITY BACKUP — MNEMONIC              ║');
    console.log('╠═══════════════════════════════════════════════════════════════╣');
    console.log('║ WRITE THESE WORDS ON PAPER. NEVER STORE DIGITALLY.          ║');
    console.log('║ This is the ONLY way to recover your identity.              ║');
    console.log('╚═══════════════════════════════════════════════════════════════╝\n');
    console.log(`Persistent ID: ${ms.getPersistentId()}`);
    console.log(`Words (${result.words.length}):\n`);
    result.words.forEach((w, i) => {
      const num = String(i + 1).padStart(2, ' ');
      process.stdout.write(`  ${num}. ${w.padEnd(16)}`);
      if ((i + 1) % 4 === 0) process.stdout.write('\n');
    });
    if (result.encrypted) {
      console.log(`\nEncrypted backup (password-protected):\n${result.encrypted}`);
    }
    console.log('\n');
    process.exit(0);
  }

  // ── CLI: yakmesh identity verify ──
  if (args[0] === 'identity' && args[1] === 'verify') {
    const MachineSeed = (await import('../identity/machine-seed.js')).default;
    const config = await loadConfig();
    const dataDir = config.node?.dataDir || './data';
    const ms = new MachineSeed(dataDir);
    await ms.init();

    // Read 33 words from remaining args
    const words = args.slice(2);
    if (words.length !== 33) {
      console.error(`\n❌ Expected 33 mnemonic words, got ${words.length}`);
      console.error('Usage: node index.js identity verify word1 word2 ... word33\n');
      process.exit(1);
    }

    const result = ms.verifyMnemonic(words);
    if (result.valid) {
      console.log('\n✅ Mnemonic verification PASSED — words match current identity.\n');
    } else {
      console.error(`\n❌ Mnemonic verification FAILED: ${result.error}\n`);
      process.exit(1);
    }
    process.exit(0);
  }

  // ── CLI: yakmesh identity restore ──
  if (args[0] === 'identity' && args[1] === 'restore') {
    const MachineSeed = (await import('../identity/machine-seed.js')).default;
    const config = await loadConfig();
    const dataDir = config.node?.dataDir || './data';

    const words = args.slice(2);
    if (words.length !== 33) {
      console.error(`\n❌ Expected 33 mnemonic words, got ${words.length}`);
      console.error('Usage: node index.js identity restore word1 word2 ... word33\n');
      process.exit(1);
    }

    try {
      const restored = MachineSeed.importFromMnemonic(words, dataDir);
      console.log('\n✅ Identity restored successfully!');
      console.log(`Persistent ID: ${restored.getPersistentId()}`);
      console.log('Restart the node to use the restored identity.\n');
    } catch (e) {
      console.error(`\n❌ Restore failed: ${e.message}\n`);
      process.exit(1);
    }
    process.exit(0);
  }

  // ── Normal startup ──
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





