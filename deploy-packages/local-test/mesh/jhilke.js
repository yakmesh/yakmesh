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
 *    key from their shared code hash (verification phrase anchor). This
 *    eliminates plaintext KEM exchange — traffic is encrypted from message #1.
 * 
 * 2. STEGANOGRAPHIC REKEY: Ongoing key rotations are coordinated via hidden
 *    signals embedded in mesh_entropy messages. No explicit REKEY messages
 *    are ever sent — an observer sees only entropy exchange.
 * 
 * Security properties:
 * - Bootstrap key is derived from code hash + node IDs (deterministic)
 * - Bootstrap key is NOT a long-term secret (upgrades to KEM immediately)
 * - Cricket signals use HKDF dialect derived from codebase hash
 * - Only nodes with identical codebase can encode/decode signals
 * - SST Fibonacci 24-cycle modulates signal encoding (rotational variety)
 * - Ternary state machine: PREPARE (+1) → READY (0) → SWITCH (-1)
 * 
 * @module mesh/jhilke
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { randomBytes } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { createLogger } from '../utils/logger.js';

// TRIBHUJ ternary primitives
import { POSITIVE, NEUTRAL, NEGATIVE } from '../oracle/tribhuj.js';

// SST Fibonacci 24-cycle for signal modulation
import { fibonacciRoot } from '../oracle/sst.js';

const log = createLogger('mesh:jhilke');

// ═══ JHILKE Configuration ═══
const JHILKE_CONFIG = {
  // Bootstrap — deterministic key from verification phrase anchor
  bootstrapSalt: 'YAKMESH-JHILKE-BOOTSTRAP-2026',
  bootstrapInfo: 'yakmesh-jhilke-bootstrap-key-v1',

  // Rekey — deterministic key rotation (no KEM round-trip)
  rekeySalt: 'YAKMESH-JHILKE-REKEY-2026',
  rekeyInfo: 'yakmesh-jhilke-rekey-v1',

  // Dialect — steganographic signal encoding
  dialectSalt: 'jhilke-cricket-salt-2026',
  dialectInfo: 'yakmesh-jhilke-dialect-v1',

  // Signal parameters
  signalInfo: 'jhilke-signal-v1',
  signalSize: 8,          // 8 bytes of HKDF output per signal
  paddingMin: 16,         // minimum random padding bytes
  paddingMax: 64,         // maximum random padding bytes

  // Timing
  tickInterval: 1000,     // 1 second ticks
  preparePhase: 3,        // ticks in PREPARE before moving to READY
  switchDelay: 3,         // ticks of SWITCH signaling before executing (must receive peer SWITCH too)
  retryAfterTicks: 24,    // "tag, you're it" retry timeout
  abortAfterCycles: 3,    // abort after 3 retry cycles (72 ticks total)
  tickTolerance: 1,       // ±1 tick tolerance for signal decoding

  // Ternary intents (TRIBHUJ trits)
  INTENT_PREPARE: POSITIVE,   // +1: I'm preparing new keys
  INTENT_READY:   NEUTRAL,    //  0: My new key is ready
  INTENT_SWITCH:  NEGATIVE,   // -1: Switching to new key now
};

/**
 * Per-peer coordination state.
 * Tracks where we are in the cricket chirp dance with each peer.
 */
class JhilkeSession {
  constructor(peerId) {
    this.peerId = peerId;
    this.state = 'idle';         // idle | prepare | ready | switch | exchanging
    this.tick = 0;               // tick when this coordination started
    this.switchTick = 0;         // tick when we entered switch state
    this.retryCount = 0;         // how many retry cycles
    this.initiator = false;      // did WE request this rekey?
    this.peerReady = false;      // has peer signaled READY?
    this.ourReady = false;       // have WE signaled READY?
    this.peerSwitchReceived = false;  // has peer signaled SWITCH?
    this.startedAt = null;
    this.lastSignalSent = null;
    this.lastSignalReceived = null;
  }

  reset() {
    this.state = 'idle';
    this.tick = 0;
    this.switchTick = 0;
    this.retryCount = 0;
    this.initiator = false;
    this.peerReady = false;
    this.ourReady = false;
    this.peerSwitchReceived = false;
    this.startedAt = null;
    this.lastSignalSent = null;
    this.lastSignalReceived = null;
  }
}


// ═══════════════════════════════════════════════════════════════════════
// JHILKE Coordinator — the cricket chorus conductor
// ═══════════════════════════════════════════════════════════════════════

export class JhilkeCoordinator {
  constructor(options) {
    this.codeHash = options.codeHash;     // Oracle code hash (same for all valid nodes)
    this.nodeId = options.nodeId;         // Our node ID
    this.annex = options.annex;           // ANNEX instance
    this.mesh = options.mesh;             // Mesh instance (for sendTo)

    // Derived seeds (deterministic from code hash — same for all nodes)
    this.dialectSeed = this._deriveDialectSeed();

    // Per-peer sessions
    this.sessions = new Map();  // peerId -> JhilkeSession

    // Tick timer
    this._tickTimer = null;
    this._globalTick = 0;

    // Stats
    this.stats = {
      bootstrapKeysDerived: 0,
      signalsSent: 0,
      signalsReceived: 0,
      signalsDecoded: 0,
      rekeyCoordinations: 0,
      rekeySuccesses: 0,
      rekeyAborts: 0,
    };

    log.info('JHILKE coordinator initialized', {
      dialectFingerprint: bytesToHex(this.dialectSeed).slice(0, 16) + '...',
    });
  }

  /**
   * Shared time reference for steganographic signal encoding/decoding.
   * Uses wall-clock seconds (Unix time) so both nodes agree on the tick
   * regardless of when they started. GPS-synchronized via MA-902 Stratum 1.
   * The per-node _globalTick is still used for session age tracking.
   */
  _sharedTick() {
    return Math.floor(Date.now() / 1000);
  }

  // ══════════════════════════════════════════════════════════════════
  // BOOTSTRAP: Deterministic initial key from shared code hash
  // "Both nodes arrive at the same conclusion because of the
  //  anchoring verification phrase" — the code hash IS the anchor.
  // ══════════════════════════════════════════════════════════════════

  /**
   * Derive a deterministic bootstrap encryption key for a peer.
   * Both nodes independently compute the SAME key because they share
   * the same code hash (enforced by the Validation Oracle + network
   * fingerprint check in HELLO/WELCOME).
   *
   * Key = HKDF(sha3_256, codeHash, sort(nodeA, nodeB), bootstrapInfo, 32)
   *
   * This key is NOT a long-term secret — anyone with source code + both
   * node IDs could theoretically compute it. It exists to:
   * 1. Eliminate plaintext KEM exchange messages entirely
   * 2. Buy seconds for JHILKE to coordinate a proper KEM upgrade
   * 3. Make ALL traffic encrypted from the very first post-handshake message
   *
   * The bootstrap key is replaced by a proper KEM key almost immediately.
   */
  deriveBootstrapKey(peerId) {
    const hashBytes = hexToBytes(this.codeHash);

    // Sort node IDs so both sides derive the same key (order-independent)
    const [first, second] = [this.nodeId, peerId].sort();
    const salt = utf8ToBytes(`${JHILKE_CONFIG.bootstrapSalt}:${first}:${second}`);
    const info = utf8ToBytes(JHILKE_CONFIG.bootstrapInfo);

    const key = hkdf(sha3_256, hashBytes, salt, info, 32);

    this.stats.bootstrapKeysDerived++;
    log.debug('Bootstrap key derived (verification phrase anchor)', {
      peer: peerId.slice(0, 16),
      keyFingerprint: bytesToHex(key).slice(0, 8) + '...',
    });

    return Buffer.from(key);
  }

  // ══════════════════════════════════════════════════════════════════
  // REKEY: Deterministic key rotation — both nodes derive the SAME
  // new key independently, no KEM round-trip, no race condition.
  // ══════════════════════════════════════════════════════════════════

  /**
   * Derive a deterministic rekey encryption key for a peer.
   * Both nodes independently compute the SAME new key because they share:
   *   - codeHash (verified by Oracle)
   *   - currentKey (established via initial KEM exchange)
   *   - epoch (incremented together after cricket coordination)
   *
   * Key = HKDF(sha3_256, SHA3(codeHash || currentKey), salt(nodeIds + epoch), rekeyInfo, 32)
   *
   * Security properties:
   *   - PFS: depends on currentKey (random from initial KEM), which is discarded after
   *   - Forward secure: each epoch is a one-way derivation from the previous
   *   - Not publicly derivable: requires knowledge of currentKey
   *   - Deterministic: no network round-trip, both sides compute simultaneously
   */
  deriveRekeyKey(peerId, epoch, currentKey) {
    // IKM = SHA3(codeHash || currentKey) — binds network identity to session secret
    const ikm = sha3_256.create()
      .update(hexToBytes(this.codeHash))
      .update(currentKey)
      .digest();

    // Sort node IDs so both sides derive the same key (order-independent)
    const [first, second] = [this.nodeId, peerId].sort();
    const salt = utf8ToBytes(`${JHILKE_CONFIG.rekeySalt}:${first}:${second}:${epoch}`);
    const info = utf8ToBytes(JHILKE_CONFIG.rekeyInfo);

    const key = hkdf(sha3_256, ikm, salt, info, 32);

    log.debug('Deterministic rekey derived', {
      peer: peerId.slice(0, 16),
      epoch,
      keyFingerprint: bytesToHex(key).slice(0, 8) + '...',
    });

    return Buffer.from(key);
  }

  // ══════════════════════════════════════════════════════════════════
  // DIALECT: Steganographic signal encoding
  // Only nodes with the same codebase can speak this language.
  // ══════════════════════════════════════════════════════════════════

  _deriveDialectSeed() {
    const hashBytes = hexToBytes(this.codeHash);
    const salt = utf8ToBytes(JHILKE_CONFIG.dialectSalt);
    const info = utf8ToBytes(JHILKE_CONFIG.dialectInfo);
    return hkdf(sha3_256, hashBytes, salt, info, 32);
  }

  /**
   * Generate a steganographic signal encoding a specific intent.
   * The signal is an 8-byte HKDF output that encodes:
   *   - both node IDs (order-sorted for determinism)
   *   - current tick
   *   - SST Fibonacci 24-cycle position (rotational modulation)
   *   - the ternary intent (+1, 0, -1)
   *
   * Only nodes sharing the dialect seed can produce or decode this signal.
   */
  _generateSignal(peerId, tick, intent) {
    const [first, second] = [this.nodeId, peerId].sort();

    // SST modulation: Fibonacci 24-cycle digital root at this tick
    const fibPos = tick % 24;
    const fibRoot = fibonacciRoot(fibPos);

    const context = utf8ToBytes(
      `${first}:${second}:${tick}:${fibPos}:${fibRoot}:${intent}`
    );

    return hkdf(sha3_256, this.dialectSeed, context,
      utf8ToBytes(JHILKE_CONFIG.signalInfo), JHILKE_CONFIG.signalSize);
  }

  /**
   * Decode an incoming signal by brute-forcing all 3 intents
   * across ±1 tick tolerance (9 total attempts).
   * Trivial for nodes sharing the dialect, impossible without it.
   */
  _decodeSignal(peerId, signalBytes, currentTick) {
    const intents = [
      JHILKE_CONFIG.INTENT_PREPARE,
      JHILKE_CONFIG.INTENT_READY,
      JHILKE_CONFIG.INTENT_SWITCH,
    ];

    const signalHex = bytesToHex(signalBytes);

    for (let offset = -JHILKE_CONFIG.tickTolerance; offset <= JHILKE_CONFIG.tickTolerance; offset++) {
      const testTick = currentTick + offset;
      if (testTick < 0) continue;

      for (const intent of intents) {
        const expected = this._generateSignal(peerId, testTick, intent);
        if (bytesToHex(expected) === signalHex) {
          return { intent, tick: testTick, offset };
        }
      }
    }

    return null;  // Not a JHILKE signal (genuine entropy)
  }


  // ══════════════════════════════════════════════════════════════════
  // COORDINATION: State machine + tick loop
  // ══════════════════════════════════════════════════════════════════

  /**
   * Start the tick loop (1-second heartbeat for cricket coordination)
   */
  start() {
    if (this._tickTimer) return;
    this._tickTimer = setInterval(() => this._tick(), JHILKE_CONFIG.tickInterval);
    log.info('JHILKE tick loop started (crickets chirping)');
  }

  /**
   * Stop the tick loop and clean up all sessions
   */
  stop() {
    if (this._tickTimer) {
      clearInterval(this._tickTimer);
      this._tickTimer = null;
    }
    this.sessions.clear();
    log.info('JHILKE tick loop stopped');
  }

  /**
   * Request a rekey for a specific peer.
   * Called by ANNEX when needsRekey() returns true.
   * Instead of sending a plaintext REKEY, we begin the cricket dance.
   */
  initiateRekey(peerId) {
    let session = this.sessions.get(peerId);
    if (session && session.state !== 'idle') {
      log.debug('JHILKE rekey already in progress', { peer: peerId.slice(0, 16) });
      return;
    }

    if (!session) {
      session = new JhilkeSession(peerId);
      this.sessions.set(peerId, session);
    }

    session.state = 'prepare';
    session.initiator = true;
    session.startedAt = Date.now();
    session.tick = this._globalTick;

    this.stats.rekeyCoordinations++;
    log.info('JHILKE rekey initiated (cricket chirping begins)', {
      peer: peerId.slice(0, 16),
      tick: this._globalTick,
    });
  }

  /**
   * Handle incoming mesh_entropy message — check for hidden cricket signals
   */
  handleIncoming(fromPeerId, message) {
    if (!message.jhilke) return;

    this.stats.signalsReceived++;

    let signalBytes;
    try {
      signalBytes = hexToBytes(message.jhilke);
    } catch {
      return;  // Malformed hex, ignore
    }

    const decoded = this._decodeSignal(fromPeerId, signalBytes, this._sharedTick());
    if (!decoded) return;  // Not a valid signal for us

    this.stats.signalsDecoded++;

    log.debug('JHILKE cricket decoded', {
      peer: fromPeerId.slice(0, 16),
      intent: decoded.intent === JHILKE_CONFIG.INTENT_PREPARE ? 'PREPARE' :
              decoded.intent === JHILKE_CONFIG.INTENT_READY   ? 'READY'   : 'SWITCH',
      tick: decoded.tick,
      offset: decoded.offset,
    });

    this._processSignal(fromPeerId, decoded);
  }

  /**
   * Process a decoded signal through the ternary state machine
   */
  _processSignal(peerId, decoded) {
    let session = this.sessions.get(peerId);

    if (!session) {
      session = new JhilkeSession(peerId);
      this.sessions.set(peerId, session);
    }

    session.lastSignalReceived = Date.now();
    const { intent } = decoded;

    switch (intent) {
      case JHILKE_CONFIG.INTENT_PREPARE:
        // Peer is preparing for rekey
        if (session.state === 'idle') {
          // They initiated — we join the coordination
          session.state = 'prepare';
          session.initiator = false;
          session.startedAt = Date.now();
          session.tick = this._globalTick;
          this.stats.rekeyCoordinations++;
          log.info('JHILKE: peer initiated rekey, joining dance', {
            peer: peerId.slice(0, 16),
          });
        }
        break;

      case JHILKE_CONFIG.INTENT_READY:
        // Peer's new key material is ready
        if (session.state === 'prepare' || session.state === 'ready') {
          session.peerReady = true;
          log.debug('JHILKE: peer ready', { peer: peerId.slice(0, 16) });

          // Both sides ready → move to switch phase
          if (session.ourReady && session.peerReady) {
            session.state = 'switch';
            session.switchTick = this._globalTick;  // Track when we entered switch state
            log.info('JHILKE: both ready, entering switch phase', { peer: peerId.slice(0, 16) });
          }
        }
        break;

      case JHILKE_CONFIG.INTENT_SWITCH:
        // Peer is switching — mark peer switch received
        session.peerSwitchReceived = true;
        // Don't execute here — let _tick() handle it after switchDelay
        if (session.state === 'ready' && session.ourReady && session.peerReady) {
          session.state = 'switch';
          session.switchTick = this._globalTick;  // Track when we entered switch state
        }
        break;
    }
  }


  /**
   * Main tick handler — drives the state machine forward.
   * Called every 1 second. Sends cricket signals and manages transitions.
   */
  _tick() {
    this._globalTick++;

    for (const [peerId, session] of this.sessions) {
      if (session.state === 'idle') continue;

      const sessionAge = this._globalTick - session.tick;

      switch (session.state) {
        case 'prepare':
          // Send PREPARE chirp
          this._sendSignal(peerId, JHILKE_CONFIG.INTENT_PREPARE);

          // After preparePhase ticks, our key material is "ready"
          if (sessionAge >= JHILKE_CONFIG.preparePhase) {
            session.ourReady = true;
            session.state = 'ready';
            log.debug('JHILKE: our key ready, signaling READY', {
              peer: peerId.slice(0, 16),
            });
          }
          break;

        case 'ready':
          // Send READY chirp
          this._sendSignal(peerId, JHILKE_CONFIG.INTENT_READY);

          // Check if both sides are ready
          if (session.ourReady && session.peerReady) {
            session.state = 'switch';
          }

          // Retry timeout: "tag, you're it"
          if (sessionAge > JHILKE_CONFIG.retryAfterTicks) {
            session.retryCount++;
            if (session.retryCount >= JHILKE_CONFIG.abortAfterCycles) {
              log.warn('JHILKE: rekey coordination timed out', {
                peer: peerId.slice(0, 16),
                retries: session.retryCount,
              });
              session.reset();
              this.stats.rekeyAborts++;
            } else {
              // Reset and retry
              session.tick = this._globalTick;
              session.peerReady = false;
              session.ourReady = false;
              session.state = 'prepare';
              log.debug('JHILKE: retry cycle', {
                peer: peerId.slice(0, 16),
                retry: session.retryCount,
              });
            }
          }
          break;

        case 'switch':
          // Send SWITCH chirp, then execute after switchDelay ticks
          this._sendSignal(peerId, JHILKE_CONFIG.INTENT_SWITCH);

          // Execute ONLY after:
          // 1. We've been in switch state for switchDelay ticks
          // 2. AND we received peer's SWITCH signal
          const switchAge = this._globalTick - (session.switchTick || session.tick);
          if (switchAge >= JHILKE_CONFIG.switchDelay && session.peerSwitchReceived) {
            this._executeSwitch(peerId, session);
          }
          break;

        case 'exchanging':
          // KEM exchange in progress via ANNEX internals — nothing to do
          break;
      }
    }

    // Periodic check: scan ANNEX sessions for rekey needs
    // (every 30 ticks = 30 seconds, matches ANNEX ping interval)
    if (this._globalTick % 30 === 0) {
      this.checkAnnexRekeys();
    }
  }

  /**
   * Send a steganographic signal (cricket chirp) to a peer
   */
  _sendSignal(peerId, intent) {
    const signal = this._generateSignal(peerId, this._sharedTick(), intent);

    // Random padding to vary message size (camouflage)
    const paddingSize = JHILKE_CONFIG.paddingMin +
      Math.floor(Math.random() * (JHILKE_CONFIG.paddingMax - JHILKE_CONFIG.paddingMin));
    const padding = bytesToHex(randomBytes(paddingSize));

    // Send as mesh_entropy — blends with normal entropy exchange traffic
    this.mesh.sendTo(peerId, {
      type: 'mesh_entropy',
      entropy: bytesToHex(randomBytes(32)),  // Genuine entropy contribution
      jhilke: bytesToHex(signal),            // Hidden cricket signal
      pad: padding,                           // Variable-size camouflage
      t: Date.now(),
    });

    this.stats.signalsSent++;

    const session = this.sessions.get(peerId);
    if (session) session.lastSignalSent = Date.now();
  }

  /**
   * Execute the actual key switch after both sides confirmed ready.
   *
   * DETERMINISTIC: Both nodes derive the SAME new key independently.
   * No KEM round-trip, no initiator/responder asymmetry, no race condition.
   * The cricket dance (PREPARE → READY → SWITCH) ensures both nodes
   * execute this at the same moment — then both compute the same key.
   */
  async _executeSwitch(peerId, session) {
    if (session.state === 'exchanging') return;
    session.state = 'exchanging';

    try {
      const annexSession = this.annex.sessions.get(peerId);
      if (!annexSession || !annexSession.encryptionKey) {
        log.warn('JHILKE: no ANNEX session for rekey switch', {
          peer: peerId.slice(0, 16),
        });
        this.stats.rekeyAborts++;
        return;
      }

      const epoch = annexSession.rekeyEpoch + 1;
      const newKey = this.deriveRekeyKey(peerId, epoch, annexSession.encryptionKey);

      // Both nodes arrive here simultaneously — switch key, no round-trip.
      annexSession.deterministicRekey(newKey, epoch);

      this.stats.rekeySuccesses++;
      log.info('JHILKE: deterministic rekey complete', {
        peer: peerId.slice(0, 16),
        epoch,
        ticks: this._globalTick - session.tick,
      });
    } catch (err) {
      log.error('JHILKE: rekey execution failed', {
        peer: peerId.slice(0, 16),
        error: err.message,
      });
      this.stats.rekeyAborts++;
    } finally {
      session.reset();
    }
  }

  /**
   * Check all ANNEX sessions for rekey needs.
   * Called periodically by the tick loop.
   */
  checkAnnexRekeys() {
    if (!this.annex) return;

    for (const [peerId, annexSession] of this.annex.sessions) {
      if (annexSession.needsRekey()) {
        this.initiateRekey(peerId);
      }
    }
  }

  /**
   * Clean up session for a disconnected peer
   */
  removePeer(peerId) {
    this.sessions.delete(peerId);
  }

  /**
   * Get JHILKE stats
   */
  getStats() {
    return {
      ...this.stats,
      activeSessions: this.sessions.size,
      activeCoordinations: [...this.sessions.values()].filter(s => s.state !== 'idle').length,
      globalTick: this._globalTick,
    };
  }
}

// Export config for testing
export { JHILKE_CONFIG };

export default JhilkeCoordinator;

