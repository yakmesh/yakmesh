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

// Phase epoch — epoch boundaries for ACT coordination
import { getCurrentEpoch, getEpochStartTime } from '../oracle/phase-epoch.js';

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

  // ACT state machine timing
  actPrepareMinTicks: 3,  // Minimum ticks in PREPARE before advancing to READY
  actSwitchDelayTicks: 2, // Ticks in SWITCH before executing
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
   * Tick tolerance is DYNAMIC — computed from three sources:
   *   1. MANI trust-level tolerance (precision of each node's time source)
   *   2. Clock drift tolerance (our correctionMs = system clock offset from GPS)
   *   3. Static floor (±1 tick minimum)
   *
   * MANI tolerance alone is insufficient: two GPS nodes (±500ms precision each)
   * can still have system clocks seconds apart. The correctionMs-based term
   * accounts for actual clock drift that Kuramoto hasn't yet converged.
   *
   * Trivial for nodes sharing the dialect, impossible without it.
   */
  _verifyChirp(peerId, signalBytes, currentTick) {
    const signalHex = bytesToHex(signalBytes);

    // Source 1: MANI trust-level tolerance (precision-based)
    const maniToleranceMs = aguwa.getToleranceForPeer(peerId);

    // Source 2: Clock drift — if our correctionMs is large, our ticks can
    // diverge from a peer whose correction differs. Add margin for the
    // peer's potential correction + network propagation.
    const driftToleranceMs = Math.abs(aguwa._correctionMs) + 2000;

    // Use the larger of MANI precision vs actual drift
    const toleranceMs = Math.max(maniToleranceMs, driftToleranceMs);
    const dynamicTicks = Math.ceil(toleranceMs / 1000);
    const tolerance = Math.max(JHILKE_CONFIG.tickTolerance, dynamicTicks);

    for (let offset = -tolerance; offset <= tolerance; offset++) {
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
    this._cleanupACT();
    this._actState = null;
    this._actPeerStates = null;
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

  // ══════════════════════════════════════════════════════════════════
  // ACT State Machine — PREPARE(+1) / READY(0) / SWITCH(-1)
  //
  // Documented design: website/docs/jhilke.html lines 1017-1100
  // PREPARE: node has consented to ACT, waiting for minimum ticks
  // READY:   minimum ticks elapsed, waiting for all consenting peers
  // SWITCH:  all peers ready, countdown to execution at epoch boundary
  //
  // Transitions driven by internal state only — never external signals.
  // ══════════════════════════════════════════════════════════════════

  /**
   * Begin ACT transition. Called after this node consents to an upgrade.
   * @param {number} targetEpoch - The AGUWA epoch at which to execute
   * @param {number} epochBufferN - Dynamic epoch buffer from propagation model (minimum 2)
   */
  beginACT(targetEpoch, epochBufferN = 2) {
    if (this._actState) {
      log.warn('ACT: Already in progress, ignoring duplicate beginACT');
      return;
    }

    this._actState = 'PREPARE';
    this._actTargetEpoch = targetEpoch;
    this._actEpochBuffer = epochBufferN;
    this._actPrepareTicks = 0;
    this._actPeerStates = new Map(); // peerId → 'PREPARE'|'READY'|'SWITCH'
    this._actTimer = setInterval(() => this._actTick(), JHILKE_CONFIG.chirpInterval);

    log.info('ACT: State machine started → PREPARE(+1)', {
      targetEpoch,
      epochBuffer: epochBufferN,
    });

    this.emit('act:state', { state: 'PREPARE', targetEpoch });
  }

  /**
   * Handle incoming ACT state announcement from a peer.
   * Peers broadcast their state via 'act:state' gossip topic.
   * @param {string} peerId
   * @param {Object} data - { state: 'PREPARE'|'READY'|'SWITCH', targetEpoch }
   */
  handleACTState(peerId, data) {
    if (!this._actState) return; // Not participating

    const { state, targetEpoch } = data;
    if (targetEpoch !== this._actTargetEpoch) return; // Different ACT round

    this._actPeerStates.set(peerId, state);

    log.debug('ACT: Peer state update', {
      peer: peerId.slice(0, 16),
      state,
      targetEpoch,
    });

    // If we're in READY and peer just went READY, check if all peers ready
    if (this._actState === 'READY') {
      this._checkAllReady();
    }
  }

  /**
   * ACT tick — driven by JHILKE chirp timer (30s cadence).
   * State transitions happen here, driven purely by internal state.
   */
  _actTick() {
    if (!this._actState) return;

    switch (this._actState) {
      case 'PREPARE':
        this._actPrepareTicks++;
        if (this._actPrepareTicks >= JHILKE_CONFIG.actPrepareMinTicks) {
          // Minimum prepare time elapsed → advance to READY
          this._actState = 'READY';
          log.info('ACT: PREPARE → READY(0)', {
            prepareTicks: this._actPrepareTicks,
            targetEpoch: this._actTargetEpoch,
          });
          this.emit('act:state', { state: 'READY', targetEpoch: this._actTargetEpoch });
          this._checkAllReady();
        } else {
          this.emit('act:state', { state: 'PREPARE', targetEpoch: this._actTargetEpoch });
        }
        break;

      case 'READY': {
        // Broadcast our READY state — waiting for peers
        this.emit('act:state', { state: 'READY', targetEpoch: this._actTargetEpoch });
        this._checkAllReady();
        break;
      }

      case 'SWITCH':
        this._actSwitchTicks++;
        if (this._actSwitchTicks >= JHILKE_CONFIG.actSwitchDelayTicks) {
          // Check AGUWA order parameter — must be ≥ 0.2 before executing
          const r = aguwa.orderParameter();
          if (r >= 0.2) {
            // Wait for epoch boundary
            const currentEpoch = getCurrentEpoch();
            if (currentEpoch >= this._actTargetEpoch) {
              log.info('ACT: SWITCH terminal — executing coordinated transition', {
                orderParameter: r.toFixed(3),
                currentEpoch,
                targetEpoch: this._actTargetEpoch,
              });
              this._actState = 'EXECUTING';
              this.emit('act:execute', { targetEpoch: this._actTargetEpoch });
              this._cleanupACT();
              return;
            }
          } else {
            log.warn('ACT: SWITCH deferred — AGUWA orderParameter too low', {
              r: r.toFixed(3),
              required: 0.2,
            });
          }
        }
        this.emit('act:state', { state: 'SWITCH', targetEpoch: this._actTargetEpoch });
        break;
    }
  }

  /**
   * Check if all consenting peers have reached READY.
   * If so, advance to SWITCH.
   */
  _checkAllReady() {
    if (this._actState !== 'READY') return;

    // If no peers tracked yet, stay in READY
    if (this._actPeerStates.size === 0) return;

    for (const [, peerState] of this._actPeerStates) {
      // Need all peers in READY or SWITCH (already past READY)
      if (peerState !== 'READY' && peerState !== 'SWITCH') return;
    }

    // All peers ready → advance to SWITCH
    this._actState = 'SWITCH';
    this._actSwitchTicks = 0;

    log.info('ACT: READY → SWITCH(-1) — all peers ready', {
      peerCount: this._actPeerStates.size,
      targetEpoch: this._actTargetEpoch,
    });

    this.emit('act:state', { state: 'SWITCH', targetEpoch: this._actTargetEpoch });
  }

  /**
   * Clean up ACT state machine timers and state.
   */
  _cleanupACT() {
    if (this._actTimer) {
      clearInterval(this._actTimer);
      this._actTimer = null;
    }
    // State preserved for inspection; cleared on next stop()
  }

  /**
   * Get current ACT state (for status/diagnostics).
   * @returns {Object|null}
   */
  getACTState() {
    if (!this._actState) return null;
    return {
      state: this._actState,
      targetEpoch: this._actTargetEpoch,
      prepareTicks: this._actPrepareTicks || 0,
      switchTicks: this._actSwitchTicks || 0,
      peerStates: Object.fromEntries(this._actPeerStates || new Map()),
    };
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

