/**
 * JHILKE — Just Hidden In-band Legitimate Key Exchange
 * झिल्के (jhilke) — the sound of crickets
 *
 * Like D-Day cricket clickers: a signal meaningful only to those who know.
 * Like Navajo codetalkers: a language outsiders can't parse.
 *
 * JHILKE provides two critical functions:
 *
 * 1. DETERMINISTIC BOOTSTRAP: Both nodes derive the same initial symmetric
 *    key from their shared code hash + per-build nonce. This eliminates
 *    plaintext KEM exchange — traffic is encrypted from message #1.
 *    The buildNonce (from manifest.json) makes the bootstrap key a per-build
 *    secret, not source-derivable.
 *
 * 2. FRIEND-OR-FOE VERIFICATION: Continuous peer integrity chirps sent
 *    every 30 seconds via mesh_entropy messages. Only nodes with the same
 *    codebase AND build nonce can produce/verify chirps. JHILKE emits
 *    'chirp:verified' and 'chirp:failed' events — it does NOT take
 *    punitive action. KARMA handles peer reputation consequences.
 *
 * Security properties:
 * - Bootstrap key = HKDF(SHA3(codeHash + buildNonce), sortedNodeIDs)
 * - Chirp dialect = HKDF(codeHash + buildNonce, dialectSalt)
 * - SST Fibonacci 24-cycle modulates chirp encoding (rotational variety)
 * - Only nodes from the same build can speak this language
 *
 * @module mesh/jhilke
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { randomBytes } from 'crypto';
import { seedStore } from '../security/prahari.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { createLogger } from '../utils/logger.js';
import { EventEmitter } from 'events';

// SST Fibonacci 24-cycle for signal modulation
import { fibonacciRoot } from '../oracle/sst.js';

// AGUWA — canonical mesh time source
import { aguwa } from './aguwa.js';

const log = createLogger('mesh:jhilke');

// ═══ JHILKE Configuration ═══
const JHILKE_CONFIG = {
  // Bootstrap — deterministic key from code hash + build nonce
  bootstrapSalt: 'YAKMESH-JHILKE-BOOTSTRAP-2026',
  bootstrapInfo: 'yakmesh-jhilke-bootstrap-key-v1',

  // Dialect — steganographic chirp encoding
  dialectSalt: 'jhilke-cricket-salt-2026',
  dialectInfo: 'yakmesh-jhilke-dialect-v1',

  // Chirp parameters
  signalInfo: 'jhilke-signal-v1',
  signalSize: 8,          // 8 bytes of HKDF output per chirp
  paddingMin: 16,         // minimum random padding bytes
  paddingMax: 64,         // maximum random padding bytes

  // Timing
  chirpInterval: 30000,   // 30 seconds — matches gossip HELLO cadence
  tickTolerance: 1,       // ±1 tick tolerance for chirp verification
};


// ═══════════════════════════════════════════════════════════════════════
// JHILKE Coordinator — the cricket chorus conductor
// ═══════════════════════════════════════════════════════════════════════

export class JhilkeCoordinator extends EventEmitter {
  constructor(options) {
    super();
    this.codeHash = options.codeHash;     // Oracle code hash (same for all valid nodes)
    this.nodeId = options.nodeId;         // Our node ID
    this.mesh = options.mesh;             // Mesh instance (for sendTo)
    this.buildNonce = options.buildNonce || null; // Per-build secret from manifest

    // Derived seeds (deterministic from code hash + buildNonce)
    this.dialectSeed = this._deriveDialectSeed();

    // Per-peer verification state
    this.peerState = new Map();  // peerId -> { lastVerifiedAt, consecutiveFailures, chirpsSent, chirpsVerified }

    // Chirp timer
    this._chirpTimer = null;

    // Stats
    this.stats = {
      bootstrapKeysDerived: 0,
      chirpsSent: 0,
      chirpsReceived: 0,
      chirpsVerified: 0,
      chirpsFailed: 0,
    };

    log.info('JHILKE coordinator initialized', {
      dialectFingerprint: bytesToHex(this.dialectSeed).slice(0, 16) + '...',
      hasBuildNonce: !!this.buildNonce,
    });
  }

  /**
   * Shared time reference for steganographic chirp encoding/verification.
   * Uses wall-clock seconds (Unix time) so both nodes agree on the tick
   * regardless of when they started. GPS-synchronized via MA-902 Stratum 1.
   */
  _sharedTick() {
    return aguwa.tick();
  }

  // ══════════════════════════════════════════════════════════════════
  // BOOTSTRAP: Deterministic initial key from code hash + build nonce
  // "Both nodes arrive at the same conclusion because of the
  //  anchoring verification phrase" — the code hash IS the anchor.
  // ══════════════════════════════════════════════════════════════════

  /**
   * Derive a deterministic bootstrap encryption key for a peer.
   * Both nodes independently compute the SAME key because they share
   * the same code hash + buildNonce (same build = same manifest).
   *
   * IKM = SHA3(codeHash + buildNonce)   — per-build secret
   * Key = HKDF(sha3_256, IKM, sort(nodeA, nodeB), bootstrapInfo, 32)
   *
   * With buildNonce, this key is NOT publicly derivable from source code
   * alone — an attacker needs the manifest from a specific build.
   * The bootstrap key is upgraded to a proper KEM-backed key via ANNEX.
   */
  deriveBootstrapKey(peerId) {
    // IKM incorporates buildNonce — makes bootstrap key per-build secret
    const ikm = sha3_256.create()
      .update(hexToBytes(this.codeHash))
      .update(utf8ToBytes(this.buildNonce || ''))
      .digest();

    // Sort node IDs so both sides derive the same key (order-independent)
    const [first, second] = [this.nodeId, peerId].sort();
    const salt = utf8ToBytes(`${JHILKE_CONFIG.bootstrapSalt}:${first}:${second}`);
    const info = utf8ToBytes(JHILKE_CONFIG.bootstrapInfo);

    const key = hkdf(sha3_256, ikm, salt, info, 32);

    this.stats.bootstrapKeysDerived++;
    log.debug('Bootstrap key derived (code hash + build nonce)', {
      peer: peerId.slice(0, 16),
      keyFingerprint: bytesToHex(key).slice(0, 8) + '...',
    });

    return Buffer.from(key);
  }

  // ══════════════════════════════════════════════════════════════════
  // DIALECT: Steganographic chirp encoding
  // Only nodes from the same build can speak this language.
  // ══════════════════════════════════════════════════════════════════

  _deriveDialectSeed() {
    // Incorporate buildNonce into dialect — different builds = different language
    const ikm = sha3_256.create()
      .update(hexToBytes(this.codeHash))
      .update(utf8ToBytes(this.buildNonce || ''))
      .digest();
    const salt = utf8ToBytes(JHILKE_CONFIG.dialectSalt);
    const info = utf8ToBytes(JHILKE_CONFIG.dialectInfo);
    return hkdf(sha3_256, ikm, salt, info, 32);
  }

  /**
   * Generate a friend-or-foe chirp for a specific peer at a given tick.
   * The chirp is an 8-byte HKDF output that encodes:
   *   - both node IDs (order-sorted for determinism)
   *   - current tick
   *   - SST Fibonacci 24-cycle position (rotational modulation)
   *
   * Only nodes sharing the dialect seed can produce or verify this chirp.
   */
  _generateChirp(peerId, tick) {
    const [first, second] = [this.nodeId, peerId].sort();

    // SST modulation: Fibonacci 24-cycle digital root at this tick
    const fibPos = tick % 24;
    const fibRoot = fibonacciRoot(fibPos);

    const context = utf8ToBytes(
      `${first}:${second}:${tick}:${fibPos}:${fibRoot}`
    );

    return hkdf(sha3_256, this.dialectSeed, context,
      utf8ToBytes(JHILKE_CONFIG.signalInfo), JHILKE_CONFIG.signalSize);
  }

  /**
   * Verify an incoming chirp from a peer.
   * Checks ±1 tick tolerance (3 attempts total).
   * Trivial for nodes sharing the dialect, impossible without it.
   */
  _verifyChirp(peerId, signalBytes, currentTick) {
    const signalHex = bytesToHex(signalBytes);

    for (let offset = -JHILKE_CONFIG.tickTolerance; offset <= JHILKE_CONFIG.tickTolerance; offset++) {
      const testTick = currentTick + offset;
      if (testTick < 0) continue;

      const expected = this._generateChirp(peerId, testTick);
      if (bytesToHex(expected) === signalHex) {
        return { valid: true, tick: testTick, offset };
      }
    }

    return { valid: false };
  }


  // ══════════════════════════════════════════════════════════════════
  // FRIEND-OR-FOE: Continuous peer integrity verification
  // ══════════════════════════════════════════════════════════════════

  /**
   * Start the chirp loop (30-second heartbeat for friend-or-foe verification)
   */
  start() {
    if (this._chirpTimer) return;
    this._chirpTimer = setInterval(() => this._chirpTick(), JHILKE_CONFIG.chirpInterval);
    log.info('JHILKE chirp loop started (crickets chirping every 30s)');
  }

  /**
   * Stop the chirp loop and clean up peer state
   */
  stop() {
    if (this._chirpTimer) {
      clearInterval(this._chirpTimer);
      this._chirpTimer = null;
    }
    this.peerState.clear();
    log.info('JHILKE chirp loop stopped');
  }

  /**
   * Handle incoming mesh_entropy message — verify friend-or-foe chirp
   */
  handleIncoming(fromPeerId, message) {
    if (!message.jhilke) return;

    this.stats.chirpsReceived++;

    let signalBytes;
    try {
      signalBytes = hexToBytes(message.jhilke);
    } catch {
      return;  // Malformed hex, ignore
    }

    const result = this._verifyChirp(fromPeerId, signalBytes, this._sharedTick());

    // Ensure peer state exists
    let state = this.peerState.get(fromPeerId);
    if (!state) {
      state = { lastVerifiedAt: null, consecutiveFailures: 0, chirpsSent: 0, chirpsVerified: 0 };
      this.peerState.set(fromPeerId, state);
    }

    if (result.valid) {
      state.lastVerifiedAt = aguwa.now();
      state.consecutiveFailures = 0;
      state.chirpsVerified++;
      this.stats.chirpsVerified++;

      this.emit('chirp:verified', { peerId: fromPeerId, tick: result.tick, offset: result.offset });

      log.trace('JHILKE chirp verified (friend)', {
        peer: fromPeerId.slice(0, 16),
        tick: result.tick,
        offset: result.offset,
      });
    } else {
      state.consecutiveFailures++;
      this.stats.chirpsFailed++;

      this.emit('chirp:failed', { peerId: fromPeerId, consecutiveFailures: state.consecutiveFailures });

      log.warn('JHILKE chirp failed (foe?)', {
        peer: fromPeerId.slice(0, 16),
        consecutiveFailures: state.consecutiveFailures,
      });
    }
  }

  /**
   * Chirp tick — send friend-or-foe chirps to all connected peers.
   * Called every 30 seconds. Blends with normal mesh_entropy traffic.
   */
  _chirpTick() {
    if (!this.mesh?.peers) return;

    for (const [peerId] of this.mesh.peers) {
      this._sendChirp(peerId);
    }
  }

  /**
   * Send a friend-or-foe chirp to a specific peer
   */
  _sendChirp(peerId) {
    const chirp = this._generateChirp(peerId, this._sharedTick());

    // Random padding to vary message size (camouflage) — PRAHARI sponge entropy
    const paddingRange = JHILKE_CONFIG.paddingMax - JHILKE_CONFIG.paddingMin;
    const paddingSize = JHILKE_CONFIG.paddingMin +
      (seedStore.squeeze(4, 'JHILKE-PADDING-SIZE').readUInt32BE(0) % paddingRange);
    const padding = bytesToHex(seedStore.squeeze(paddingSize, 'JHILKE-PADDING'));

    // Send as mesh_entropy — blends with normal entropy exchange traffic
    this.mesh.sendTo(peerId, {
      type: 'mesh_entropy',
      entropy: bytesToHex(seedStore.squeeze(32, 'JHILKE-ENTROPY')),  // Genuine entropy contribution
      jhilke: bytesToHex(chirp),             // Hidden cricket chirp
      pad: padding,                           // Variable-size camouflage
      t: aguwa.now(),
    });

    this.stats.chirpsSent++;

    // Track chirps sent per peer
    let state = this.peerState.get(peerId);
    if (!state) {
      state = { lastVerifiedAt: null, consecutiveFailures: 0, chirpsSent: 0, chirpsVerified: 0 };
      this.peerState.set(peerId, state);
    }
    state.chirpsSent++;
  }

  /**
   * Clean up state for a disconnected peer
   */
  cleanupPeer(peerId) {
    this.peerState.delete(peerId);
  }

  /**
   * Get JHILKE stats
   */
  getStats() {
    return {
      ...this.stats,
      peerCount: this.peerState.size,
    };
  }
}

// Export config for testing
export { JHILKE_CONFIG };

export default JhilkeCoordinator;

