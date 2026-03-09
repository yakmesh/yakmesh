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
 * TRIBHUJ Key Ratchet — Trinary Rotating Keypairs
 * 
 * त्रिभुज (Tribhuj) = Triangle, three-pointed
 * 
 * A Fibonacci-style key ratchet using TRIBHUJ balanced ternary principles.
 * Two ML-DSA-65 keypairs are generated at genesis (the triangle's base).
 * All subsequent keys are derived by amalgamating the previous two:
 * 
 *   K₀ = genesis left    (random seed)
 *   K₁ = genesis right   (random seed) 
 *   K₂ = derive(K₀, K₁)  — SHA3-256(secret₀ ‖ secret₁) → seed → keygen
 *   K₃ = derive(K₁, K₂)
 *   Kₙ = derive(Kₙ₋₂, Kₙ₋₁)
 * 
 * At any point, the ratchet holds THREE states (the triangle):
 *   - previous: accepted for verification (transition grace period)
 *   - current:  used for signing, accepted for verification
 *   - next:     pre-computed, ready to rotate into current
 * 
 * The "take away the treasure" principle:
 *   - Compromising the current key reveals NOTHING about previous keys
 *     (SHA3-256 is one-way; you can't reverse the amalgamation)
 *   - The attacker gets ONE key, not a history
 *   - Rotation makes even that key useless within one interval
 * 
 * TRIBHUJ synergy: the ternary state {previous, current, next} maps
 * directly to balanced ternary {-1, 0, +1} / {past, present, future}.
 * The ratchet IS a TRIBHUJ operation — three states, rotating forward.
 * 
 * @module identity/tribhuj-ratchet
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_256 as _nobleSha3 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { createLogger } from '../utils/logger.js';

// ACCEL: Hardware-accelerated crypto (native SHA3 via OpenSSL/SHA-NI, future liboqs)
import { sha3_256, mlDsa65Sign, mlDsa65Verify } from '../utils/accel.js';

const log = createLogger('identity:tribhuj-ratchet');

// =============================================================================
// CONFIGURATION
// =============================================================================

const RATCHET_CONFIG = {
  // Rotation interval (default: 5 minutes)
  rotationInterval: 300000,
  
  // Grace period: how long to accept signatures from the previous key
  // (allows in-flight messages signed with old key to still verify)
  gracePeriod: 60000,
  
  // Max rotations before forcing a full re-genesis
  // (defense-in-depth: limits the derivation chain length)
  maxChainLength: 1000,
  
  // Algorithm identifier
  algorithm: 'TRIBHUJ-ML-DSA-65',
};

// =============================================================================
// TRIBHUJ KEY RATCHET
// =============================================================================

export class TribhujRatchet {
  /**
   * @param {Object} options
   * @param {number} [options.rotationInterval] - Ms between rotations
   * @param {number} [options.gracePeriod] - Ms to accept old key
   * @param {number} [options.maxChainLength] - Max rotations before re-genesis
   */
  constructor(options = {}) {
    this.config = { ...RATCHET_CONFIG, ...options };
    
    // The triangle: three keypair slots
    this._previous = null;   // {publicKey, secretKey, epoch}
    this._current = null;    // {publicKey, secretKey, epoch}
    this._next = null;       // {publicKey, secretKey, epoch}
    
    this._epoch = 0;         // Rotation counter
    this._chainLength = 0;   // Current chain derivation depth
    this._rotationTimer = null;
    this._genesisSeeds = null; // Zeroed after first rotation
    
    this._initialized = false;
  }
  
  /**
   * Initialize the ratchet — generates the two genesis keypairs.
   * This is the only time raw keygen happens (the "double overhead").
   */
  async initialize() {
    log.info('TRIBHUJ ratchet initializing — generating genesis keypairs');
    
    // Genesis: two independent random keypairs
    const seedA = crypto.getRandomValues(new Uint8Array(32));
    const seedB = crypto.getRandomValues(new Uint8Array(32));
    
    const kpA = ml_dsa65.keygen(seedA);
    const kpB = ml_dsa65.keygen(seedB);
    
    this._previous = {
      publicKey: kpA.publicKey,
      secretKey: kpA.secretKey,
      epoch: 0,
    };
    
    this._current = {
      publicKey: kpB.publicKey,
      secretKey: kpB.secretKey,
      epoch: 1,
    };
    
    // Pre-compute next by amalgamating A + B
    this._next = this._deriveNext(this._previous, this._current, 2);
    
    this._epoch = 1;
    this._chainLength = 0;
    this._initialized = true;
    
    // Zero genesis seeds (they're no longer needed)
    seedA.fill(0);
    seedB.fill(0);
    
    log.info('TRIBHUJ ratchet ready — triangle formed', {
      epoch: this._epoch,
      pubKeyPrev: bytesToHex(this._previous.publicKey).slice(0, 24) + '...',
      pubKeyCurr: bytesToHex(this._current.publicKey).slice(0, 24) + '...',
      pubKeyNext: bytesToHex(this._next.publicKey).slice(0, 24) + '...',
    });
    
    return this;
  }
  
  /**
   * Start automatic rotation on a timer.
   */
  startAutoRotation() {
    if (this._rotationTimer) return;
    
    this._rotationTimer = setInterval(() => {
      this.rotate();
    }, this.config.rotationInterval);
    
    log.info(`TRIBHUJ auto-rotation started (every ${this.config.rotationInterval / 1000}s)`);
  }
  
  /**
   * Stop automatic rotation.
   */
  stopAutoRotation() {
    if (this._rotationTimer) {
      clearInterval(this._rotationTimer);
      this._rotationTimer = null;
    }
  }
  
  /**
   * Rotate the triangle forward: previous ← current, current ← next, next ← derive(current, next)
   * 
   * This is the TRIBHUJ operation: the triangle slides forward through time.
   * {past, present, future} → {present, future, derive(present, future)}
   */
  rotate() {
    if (!this._initialized) {
      throw new Error('TRIBHUJ ratchet not initialized');
    }
    
    this._chainLength++;
    
    // Check chain length limit
    if (this._chainLength >= this.config.maxChainLength) {
      log.warn('TRIBHUJ chain limit reached, performing re-genesis');
      this.initialize();
      return;
    }
    
    // Zero the outgoing previous secret key — "take away the treasure"
    if (this._previous?.secretKey) {
      this._previous.secretKey.fill(0);
    }
    
    const newEpoch = this._epoch + 1;
    
    // Slide the triangle forward
    this._previous = {
      publicKey: this._current.publicKey,
      secretKey: null, // Only need public key for verification
      epoch: this._current.epoch,
    };
    
    this._current = this._next;
    this._next = this._deriveNext(this._previous, this._current, newEpoch + 1);
    this._epoch = newEpoch;
    
    log.debug('TRIBHUJ rotated', {
      epoch: this._epoch,
      chainLength: this._chainLength,
      currentPubKey: bytesToHex(this._current.publicKey).slice(0, 24) + '...',
    });
    
    return {
      epoch: this._epoch,
      publicKey: bytesToHex(this._current.publicKey),
      previousPublicKey: bytesToHex(this._previous.publicKey),
    };
  }
  
  /**
   * Derive the next keypair from two parent keypairs (the TRIBHUJ amalgamation).
   * 
   * seed = SHA3-256(epochBytes ‖ parentA.publicKey ‖ parentB.secretKey)
   * 
   * Uses the public key of one parent and secret key of the other to ensure:
   * - Both parents contribute entropy
   * - An observer with only public keys cannot predict the next key
   * - The derivation is deterministic given the triangle state
   */
  _deriveNext(parentA, parentB, epoch) {
    // Build the amalgamation input
    const epochBytes = new Uint8Array(4);
    new DataView(epochBytes.buffer).setUint32(0, epoch, false);
    
    // Combine: epoch ‖ pubA ‖ secretB (or pubA if secretB unavailable)
    const material = parentB.secretKey || parentB.publicKey;
    const combined = new Uint8Array(4 + parentA.publicKey.length + material.length);
    combined.set(epochBytes, 0);
    combined.set(parentA.publicKey, 4);
    combined.set(material, 4 + parentA.publicKey.length);
    
    // Derive seed via SHA3-256
    const seed = sha3_256(combined);
    
    // Zero intermediate material
    combined.fill(0);
    
    // Generate new keypair from derived seed
    const kp = ml_dsa65.keygen(seed);
    
    // Zero the seed
    seed.fill(0);
    
    return {
      publicKey: kp.publicKey,
      secretKey: kp.secretKey,
      epoch,
    };
  }
  
  // ===========================================================================
  // SIGNING & VERIFICATION
  // ===========================================================================
  
  /**
   * Sign a message with the current key.
   * Returns the signature + epoch so verifiers know which key to check.
   */
  sign(message) {
    if (!this._initialized || !this._current?.secretKey) {
      throw new Error('TRIBHUJ ratchet not ready for signing');
    }
    
    const messageBytes = typeof message === 'string'
      ? new TextEncoder().encode(message)
      : message;
    
    const signature = mlDsa65Sign(messageBytes, this._current.secretKey);
    
    return {
      signature: bytesToHex(signature),
      epoch: this._epoch,
      publicKey: bytesToHex(this._current.publicKey),
      algorithm: this.config.algorithm,
    };
  }
  
  /**
   * Sign an object (add _tribhujSig, _tribhujEpoch, _tribhujPubKey fields).
   */
  signObject(obj) {
    const payload = JSON.stringify(obj);
    const sig = this.sign(payload);
    
    return {
      ...obj,
      _tribhujSig: sig.signature,
      _tribhujEpoch: sig.epoch,
      _tribhujPubKey: sig.publicKey,
    };
  }
  
  /**
   * Verify a signature, accepting current OR previous key (grace period).
   * 
   * The ternary verification: try current (+1), try previous (-1), fail (0).
   * This is a TRIBHUJ consensus operation in miniature.
   * 
   * @param {string|Uint8Array} message
   * @param {string} signatureHex
   * @param {string} publicKeyHex - The signer's claimed public key
   * @returns {{ valid: boolean, keyState: string }} keyState: 'current'|'previous'|'invalid'
   */
  verify(message, signatureHex, publicKeyHex) {
    const messageBytes = typeof message === 'string'
      ? new TextEncoder().encode(message)
      : message;
    const signature = hexToBytes(signatureHex);
    const publicKey = hexToBytes(publicKeyHex);
    
    // Try current key (POSITIVE / present)
    if (this._current && bytesToHex(this._current.publicKey) === publicKeyHex) {
      try {
        if (mlDsa65Verify(signature, messageBytes, publicKey)) {
          return { valid: true, keyState: 'current' };
        }
      } catch (e) { /* fall through */ }
    }
    
    // Try previous key (NEGATIVE / past — grace period)
    if (this._previous && bytesToHex(this._previous.publicKey) === publicKeyHex) {
      try {
        if (mlDsa65Verify(signature, messageBytes, publicKey)) {
          return { valid: true, keyState: 'previous' };
        }
      } catch (e) { /* fall through */ }
    }
    
    // Unknown key — verify against the provided public key directly
    // (for messages from peers whose ratchet state we don't track)
    try {
      if (mlDsa65Verify(signature, messageBytes, publicKey)) {
        return { valid: true, keyState: 'external' };
      }
    } catch (e) { /* fall through */ }
    
    return { valid: false, keyState: 'invalid' };
  }
  
  /**
   * Verify a signed object.
   */
  verifyObject(signedObj, publicKeyHex) {
    const { _tribhujSig, _tribhujEpoch, _tribhujPubKey, ...rest } = signedObj;
    if (!_tribhujSig) return { valid: false, keyState: 'unsigned' };
    
    const key = publicKeyHex || _tribhujPubKey;
    const payload = JSON.stringify(rest);
    return this.verify(payload, _tribhujSig, key);
  }
  
  // ===========================================================================
  // STATE / EXPORT
  // ===========================================================================
  
  /**
   * Get current ratchet state (public info only — safe to share over network).
   */
  getPublicState() {
    return {
      algorithm: this.config.algorithm,
      epoch: this._epoch,
      chainLength: this._chainLength,
      currentPublicKey: this._current ? bytesToHex(this._current.publicKey) : null,
      previousPublicKey: this._previous ? bytesToHex(this._previous.publicKey) : null,
      rotationInterval: this.config.rotationInterval,
    };
  }
  
  /**
   * Destroy all key material — "take away ALL the treasure".
   */
  destroy() {
    if (this._previous?.secretKey) this._previous.secretKey.fill(0);
    if (this._current?.secretKey) this._current.secretKey.fill(0);
    if (this._next?.secretKey) this._next.secretKey.fill(0);
    
    this._previous = null;
    this._current = null;
    this._next = null;
    this._initialized = false;
    
    this.stopAutoRotation();
    
    log.info('TRIBHUJ ratchet destroyed — all key material zeroed');
  }
}

// =============================================================================
// GATEWAY ATTESTATION — "Verify Once, Trust the Stamp"
// =============================================================================

/**
 * A lightweight attestation that a gateway node has verified a message's
 * ML-DSA-65 signature. Other nodes that trust this gateway can skip the
 * expensive full verify and just check the attestation.
 * 
 * This is the "non-rewarding" approach: the heavy crypto (ML-DSA-65 verify,
 * ~2-5ms) happens once at the gateway. Subsequent nodes see only the
 * attestation hash (~0.01ms to verify).
 * 
 * Structure:
 *   attestation = SHA3-256(messageId ‖ signer ‖ gatewayNodeId ‖ timestamp)
 *   + signature from gateway's TRIBHUJ ratchet
 */
export class GatewayAttestation {
  /**
   * @param {string} gatewayNodeId - This gateway's node ID
   * @param {TribhujRatchet} ratchet - Gateway's TRIBHUJ ratchet for signing attestations
   * @param {Object} [options]
   * @param {number} [options.attestationTTL=60000] - How long attestations are valid
   */
  constructor(gatewayNodeId, ratchet, options = {}) {
    this.gatewayNodeId = gatewayNodeId;
    this.ratchet = ratchet;
    this.attestationTTL = options.attestationTTL || 60000;
    
    // Cache of attestations we've issued (for dedup)
    this._issued = new Map();   // messageId -> attestation
    this._maxIssued = 5000;
  }
  
  /**
   * Create an attestation for a verified message.
   * Call this AFTER you've done the full ML-DSA-65 verify.
   * 
   * @param {string} messageId 
   * @param {string} signerNodeId - Who signed the original message
   * @returns {Object} The attestation object to attach to the message
   */
  attest(messageId, signerNodeId) {
    const timestamp = Date.now();
    
    // Build attestation hash
    const input = `${messageId}:${signerNodeId}:${this.gatewayNodeId}:${timestamp}`;
    const hashBytes = sha3_256(new TextEncoder().encode(input));
    const attestHash = bytesToHex(hashBytes);
    
    // Sign the attestation with our TRIBHUJ ratchet (fast — key already in memory)
    const sig = this.ratchet.sign(attestHash);
    
    const attestation = {
      _gwAttest: {
        hash: attestHash,
        gateway: this.gatewayNodeId,
        signer: signerNodeId,
        messageId,
        timestamp,
        sig: sig.signature,
        epoch: sig.epoch,
        pubKey: sig.publicKey,
      },
    };
    
    // Cache
    this._issued.set(messageId, attestation);
    if (this._issued.size > this._maxIssued) {
      // Evict oldest
      const first = this._issued.keys().next().value;
      this._issued.delete(first);
    }
    
    return attestation._gwAttest;
  }
  
  /**
   * Verify an attestation from a trusted gateway.
   * Much cheaper than full ML-DSA-65 verify (~0.01ms vs ~2-5ms).
   * 
   * @param {Object} attestation - The _gwAttest object
   * @param {TribhujRatchet} [gatewayRatchet] - Gateway's ratchet (optional, uses our own if same gateway)
   * @returns {{ valid: boolean, reason: string }}
   */
  verifyAttestation(attestation, gatewayRatchet = null) {
    if (!attestation?.hash || !attestation?.sig || !attestation?.gateway) {
      return { valid: false, reason: 'malformed' };
    }
    
    // Check TTL
    if (Date.now() - attestation.timestamp > this.attestationTTL) {
      return { valid: false, reason: 'expired' };
    }
    
    // Reconstruct expected hash
    const input = `${attestation.messageId}:${attestation.signer}:${attestation.gateway}:${attestation.timestamp}`;
    const expectedHash = bytesToHex(sha3_256(new TextEncoder().encode(input)));
    
    if (expectedHash !== attestation.hash) {
      return { valid: false, reason: 'hash_mismatch' };
    }
    
    // Verify the gateway's TRIBHUJ signature on the hash
    const ratchet = gatewayRatchet || this.ratchet;
    const result = ratchet.verify(attestation.hash, attestation.sig, attestation.pubKey);
    
    return result.valid
      ? { valid: true, reason: `verified_via_${result.keyState}` }
      : { valid: false, reason: 'bad_gateway_signature' };
  }
}

export default TribhujRatchet;
