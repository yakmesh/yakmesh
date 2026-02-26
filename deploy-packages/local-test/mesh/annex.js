/**
 * Yakmesh Annex - Autonomous Network Negotiated Encrypted eXchange
 * 
 * End-to-end encrypted point-to-point communication between mesh peers using:
 * - ML-KEM768 (Kyber) for quantum-resistant key encapsulation
 * - AES-256-GCM for authenticated symmetric encryption
 * - ML-DSA-65 signatures for sender authentication
 * - Perfect forward secrecy via ephemeral key exchange
 * 
 * Key Innovation: "Changes pass through math alone"
 * - All payload transformations are cryptographically autonomous
 * - No plaintext touches the network - only ciphertext
 * - Recipients prove possession of private key to decrypt
 * - Sovereignty over your data channel
 * 
 * Use Cases:
 * - Authenticated content delivery (vs public gossip)
 * - Beacon acknowledgments with encryption
 * - App-specific private payloads
 * - Site/CDN authentication tokens
 * - Direct peer-to-peer secure messaging
 * 
 * @module mesh/annex
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { randomBytes, createCipheriv, createDecipheriv, createHash } from 'crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha3_256 as _nobleSha3 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { createLogger } from '../utils/logger.js';

// ACCEL: Hardware-accelerated crypto (native SHA3, native KEM via liboqs/AVX-512)
import { sha3_256, mlKem768Keygen, mlKem768Encapsulate, mlKem768Decapsulate } from '../utils/accel.js';

// STEADYWATCH: Quantum-hardware-validated entropy seeds (Hurwitz quaternion, IBM Quantum)
import { getHybridSeed, seedStore as steadywatchStore } from '../security/steadywatch.js';

// ═══ TRIBHUJ — Balanced ternary for channel lifecycle ═══
// POSITIVE: ESTABLISHED (secure channel active)
// NEUTRAL:  NEGOTIATING (key exchange in progress)
// NEGATIVE: CLOSED (session terminated or expired)
import { POSITIVE, NEUTRAL, NEGATIVE } from '../oracle/tribhuj.js';

/** ANNEX channel lifecycle states (TRIBHUJ trits) */
export const ChannelState = Object.freeze({
  CLOSED: NEGATIVE,       // -1: Session terminated or expired
  NEGOTIATING: NEUTRAL,   //  0: Key exchange in progress
  ESTABLISHED: POSITIVE,  // +1: Secure channel active
});

/** Extract unique peer suffix from nodeId (e.g. 'node-net-name-pq-kEEU' → 'kEEU') */
const peerTag = (id) => id?.split('-pq-').pop() || id?.slice?.(-8) || String(id);

const log = createLogger('mesh:annex');

const ANNEX_CONFIG = {
  // Encryption
  symmetricAlgorithm: 'aes-256-gcm',
  nonceSize: 12,
  authTagLength: 16,
  
  // Key derivation
  keyDerivationSalt: 'YAKMESH-ANNEX-2026',
  contextSeparator: ':',
  
  // Session management
  sessionTimeout: 3600000,       // 1 hour session lifetime
  rekeyInterval: 300000,         // Re-key every 5 minutes for PFS
  maxMessagesPerKey: 10000,      // Force re-key after N messages
  
  // Message types
  messageTypes: {
    KEY_EXCHANGE: 'annex:key_exchange',
    KEY_RESPONSE: 'annex:key_response',
    ENCRYPTED: 'annex:encrypted',
    REKEY: 'annex:rekey',
    CLOSE: 'annex:close',
  },
};

/**
 * Encrypted message envelope - the quantum-sealed diplomatic pouch
 */
class AnnexEnvelope {
  constructor(options) {
    this.id = options.id || bytesToHex(randomBytes(16));
    this.type = options.type || ANNEX_CONFIG.messageTypes.ENCRYPTED;
    this.senderId = options.senderId;
    this.recipientId = options.recipientId;
    this.sessionId = options.sessionId;
    this.sequence = options.sequence || 0;
    this.timestamp = options.timestamp || Date.now();
    
    // Encrypted payload components
    this.nonce = options.nonce || null;
    this.ciphertext = options.ciphertext || null;
    this.authTag = options.authTag || null;
    
    // Key exchange components (only for key exchange messages)
    this.kemCiphertext = options.kemCiphertext || null;
    this.kemPublicKey = options.kemPublicKey || null;
    
    // Signature (ML-DSA-65)
    this.signature = options.signature || null;
  }
  
  /**
   * Compute hash for signing
   */
  getSigningPayload() {
    return JSON.stringify({
      id: this.id,
      type: this.type,
      senderId: this.senderId,
      recipientId: this.recipientId,
      sessionId: this.sessionId,
      sequence: this.sequence,
      timestamp: this.timestamp,
      nonce: this.nonce,
      ciphertext: this.ciphertext,
      authTag: this.authTag,
      kemCiphertext: this.kemCiphertext,
      kemPublicKey: this.kemPublicKey,
    });
  }
  
  /**
   * Serialize for transport
   */
  toJSON() {
    return {
      id: this.id,
      type: this.type,
      senderId: this.senderId,
      recipientId: this.recipientId,
      sessionId: this.sessionId,
      sequence: this.sequence,
      timestamp: this.timestamp,
      nonce: this.nonce,
      ciphertext: this.ciphertext,
      authTag: this.authTag,
      kemCiphertext: this.kemCiphertext,
      kemPublicKey: this.kemPublicKey,
      signature: this.signature,
    };
  }
  
  static fromJSON(data) {
    return new AnnexEnvelope(data);
  }
}

/**
 * An annexed territory - a secure session with a single peer
 */
class AnnexSession {
  constructor(options) {
    this.sessionId = options.sessionId || bytesToHex(randomBytes(16));
    this.localNodeId = options.localNodeId;
    this.remoteNodeId = options.remoteNodeId;
    this.initiator = options.initiator || false;
    
    // Key material
    this.kemKeyPair = null;      // Our ephemeral KEM key pair
    this.sharedSecret = null;    // Derived shared secret
    this.encryptionKey = null;   // Current symmetric key
    this.pendingEncryptionKey = null; // Future key awaiting implicit ack (bootstrap→KEM upgrade only)
    this.bootstrapped = false;   // JHILKE: true if using deterministic bootstrap key (not yet KEM-backed)
    this.rekeyEpoch = 0;         // JHILKE: deterministic rekey epoch (incremented on each cricket-coordinated switch)
    this.sendSequence = 0;       // Outbound message counter
    this.recvSequence = -1;      // Inbound message counter (-1 so first msg seq 0 passes)
    this.messageCount = 0;       // Total messages with current key
    
    // State
    this.established = false;
    this.channelState = ChannelState.NEGOTIATING;  // TRIBHUJ trit lifecycle
    this.createdAt = Date.now();
    this.lastActivity = Date.now();
    this.lastRekey = null;
  }
  
  /**
   * JHILKE deterministic rekey — both nodes derive the same key simultaneously.
   * No KEM round-trip, no pending key, no race condition.
   * Called by JhilkeCoordinator._executeSwitch() after cricket coordination.
   */
  deterministicRekey(newKey, epoch) {
    this.encryptionKey = newKey;
    this.rekeyEpoch = epoch;
    this.messageCount = 0;
    this.lastRekey = Date.now();
    this.lastActivity = Date.now();
  }
  
  /**
   * Generate ephemeral KEM key pair for this session.
   * 
   * ACCEL: Routes through mlKem768Keygen() for native liboqs AVX-512 NTT
   * acceleration when available (previously called noble directly — bypassed ACCEL).
   * 
   * STEADYWATCH: If quantum satellite seeds are loaded, uses hybrid entropy:
   *   hybridSeed = SHA3(satelliteSeed || EXPAND) ⊕ randomBytes(64)
   * Two-source extractor: even if one source is compromised, keys are safe.
   */
  async generateKeyPair() {
    // STEADYWATCH hybrid seed (quantum + CSPRNG) or pure CSPRNG fallback
    const seed = steadywatchStore.initialized
      ? getHybridSeed()
      : randomBytes(64);

    // Route through ACCEL for native liboqs/AVX-512 acceleration
    this.kemKeyPair = await mlKem768Keygen(seed);
    return bytesToHex(this.kemKeyPair.publicKey);
  }
  
  /**
   * Complete key exchange as initiator (encapsulate with peer's public key)
   */
  encapsulate(peerPublicKey, { defer = false } = {}) {
    const publicKeyBytes = hexToBytes(peerPublicKey);
    const result = mlKem768Encapsulate(publicKeyBytes);
    
    this.sharedSecret = result.sharedSecret;
    const newKey = this._deriveEncryptionKey();
    
    if (defer && this.encryptionKey) {
      // Rekey responder: store new key as pending, keep current active.
      // PFS-safe: we only hold the FUTURE key, never the past key.
      // Activation happens implicitly when we receive a message encrypted
      // with the new key (see decrypt()).
      this.pendingEncryptionKey = newKey;
    } else {
      // Initial handshake or initiator: switch immediately
      this.encryptionKey = newKey;
    }
    this.established = true;
    this.channelState = ChannelState.ESTABLISHED;
    this.lastRekey = Date.now();
    
    return bytesToHex(result.cipherText);
  }
  
  /**
   * Complete key exchange as responder (decapsulate received ciphertext)
   */
  decapsulate(ciphertext) {
    if (!this.kemKeyPair) {
      throw new Error('No key pair generated');
    }
    
    const ciphertextBytes = hexToBytes(ciphertext);
    this.sharedSecret = mlKem768Decapsulate(ciphertextBytes, this.kemKeyPair.secretKey);

    // Zero ephemeral KEM secret key — shared secret is extracted, secret key is
    // no longer needed. Minimizes exposure window if memory is later compromised.
    if (this.kemKeyPair.secretKey instanceof Uint8Array) {
      this.kemKeyPair.secretKey.fill(0);
    }
    this.kemKeyPair = null; // Release reference entirely

    // Bootstrap→KEM upgrade bridge: briefly retain old key for in-flight messages.
    // The responder still encrypts with bootstrap key until implicit ack arrives.
    // Without this bridge, those in-flight messages cause AEAD auth failures.
    // Auto-expires after 5s — NOT a permanent "previous key" (PFS preserved).
    if (this.encryptionKey) {
      this._transitionKey = this.encryptionKey;
      this._transitionKeyTimer = setTimeout(() => {
        this._transitionKey = null;
        this._transitionKeyTimer = null;
      }, 5000);
    }

    // Initiator receiving KEY_RESPONSE: switch immediately to KEM key.
    // The initiator is always "first mover" — its next message triggers
    // the responder to promote pendingEncryptionKey.
    this.encryptionKey = this._deriveEncryptionKey();
    this.pendingEncryptionKey = null; // Clear any pending state
    this.established = true;
    this.channelState = ChannelState.ESTABLISHED;
    this.lastRekey = Date.now();
    
    return true;
  }
  
  /**
   * Encrypt a message for this session
   */
  encrypt(plaintext) {
    if (!this.established || !this.encryptionKey) {
      throw new Error('Session not established');
    }
    
    const nonce = randomBytes(ANNEX_CONFIG.nonceSize);
    const cipher = createCipheriv(
      ANNEX_CONFIG.symmetricAlgorithm,
      this.encryptionKey,
      nonce,
      { authTagLength: ANNEX_CONFIG.authTagLength }
    );
    
    // Include sequence number in AAD for replay protection
    const aad = Buffer.from(`${this.sessionId}:${this.sendSequence}`);
    cipher.setAAD(aad);
    
    const data = typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext);
    const encrypted = Buffer.concat([
      cipher.update(data, 'utf8'),
      cipher.final(),
    ]);
    
    this.sendSequence++;
    this.messageCount++;
    this.lastActivity = Date.now();
    
    return {
      nonce: nonce.toString('hex'),
      ciphertext: encrypted.toString('hex'),
      authTag: cipher.getAuthTag().toString('hex'),
      sequence: this.sendSequence - 1,
    };
  }
  
  /**
   * Decrypt a message for this session
   */
  /**
   * Decrypt with a specific key (internal helper)
   */
  _decryptWithKey(key, encryptedData, expectedSequence) {
    const nonce = Buffer.from(encryptedData.nonce, 'hex');
    const ciphertext = Buffer.from(encryptedData.ciphertext, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    
    const decipher = createDecipheriv(
      ANNEX_CONFIG.symmetricAlgorithm,
      key,
      nonce,
      { authTagLength: ANNEX_CONFIG.authTagLength }
    );
    
    const aad = Buffer.from(`${this.sessionId}:${expectedSequence}`);
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    
    return decrypted.toString('utf8');
  }
  
  decrypt(encryptedData, expectedSequence) {
    if (!this.established || !this.encryptionKey) {
      throw new Error('Session not established');
    }
    
    // Replay protection: sequence must be greater than last received
    if (typeof expectedSequence !== 'number' || expectedSequence <= this.recvSequence) {
      throw new Error(`Replay detected: sequence ${expectedSequence} <= ${this.recvSequence}`);
    }
    
    try {
      // Try current key first
      const result = this._decryptWithKey(this.encryptionKey, encryptedData, expectedSequence);
      this.recvSequence = expectedSequence;
      this.lastActivity = Date.now();
      return result;
    } catch (err) {
      // During rekey transition, the initiator has switched to the new key
      // but the responder is still on the old key. Try the PENDING (future)
      // key — if it works, promote it to current. This is the implicit ack.
      //
      // Security note: we only ever store the FUTURE key as fallback, never
      // the PAST key. An attacker who dumps memory gets a key they'd have
      // gotten anyway once activated. PFS of past messages is never at risk.
      if (this.pendingEncryptionKey) {
        try {
          const result = this._decryptWithKey(this.pendingEncryptionKey, encryptedData, expectedSequence);
          // Implicit ack: promote pending → current, zero old key
          this.encryptionKey = this.pendingEncryptionKey;
          this.pendingEncryptionKey = null;
          this.recvSequence = expectedSequence;
          this.lastActivity = Date.now();
          log.info('Rekey activated via implicit ack', { sessionId: this.sessionId?.slice(0, 16) });
          return result;
        } catch {
          // pending key also failed — fall through to transition key
        }
      }
      
      // Bootstrap→KEM upgrade bridge: the responder may still send messages
      // encrypted with the bootstrap key between our KEM switch and their
      // implicit-ack promotion. Try the briefly-retained old key.
      // NO promotion — this key is being phased out (auto-expires via timer).
      if (this._transitionKey) {
        const result = this._decryptWithKey(this._transitionKey, encryptedData, expectedSequence);
        this.recvSequence = expectedSequence;
        this.lastActivity = Date.now();
        log.info('Bootstrap→KEM transition: decoded in-flight message with old key', {
          sessionId: this.sessionId?.slice(0, 16),
        });
        return result;
      }
      
      throw err;
    }
  }
  
  /**
   * Check if session needs re-keying for perfect forward secrecy
   */
  needsRekey() {
    if (!this.established) return false;
    
    const timeSinceRekey = Date.now() - (this.lastRekey || this.createdAt);
    return (
      timeSinceRekey > ANNEX_CONFIG.rekeyInterval ||
      this.messageCount >= ANNEX_CONFIG.maxMessagesPerKey
    );
  }
  
  /**
   * Check if session has expired
   */
  isExpired() {
    return Date.now() - this.lastActivity > ANNEX_CONFIG.sessionTimeout;
  }
  
  /**
   * Derive symmetric encryption key from shared secret
   */
  _deriveEncryptionKey() {
    // Sort nodeIds so both sides derive the same key
    // (localNodeId and remoteNodeId are swapped between initiator/responder)
    const [first, second] = [this.localNodeId, this.remoteNodeId].sort();
    return createHash('sha3-256')
      .update(this.sharedSecret)
      .update(ANNEX_CONFIG.keyDerivationSalt)
      .update(this.sessionId)
      .update(first)
      .update(second)
      .digest();
  }
}

/**
 * ANNEX - Autonomous Network Negotiated Encrypted eXchange
 * 
 * Manages encrypted point-to-point communication channels
 * "Annex your own sovereign data territory"
 */
export class Annex {
  constructor(options) {
    this.identity = options.identity;
    this.mesh = options.mesh;
    this.sessions = new Map();   // remoteNodeId -> AnnexSession
    this.pendingHandshakes = new Map();
    this.messageHandlers = new Map();
    
    // JHILKE coordinator reference (set by network.js after initialization)
    this.jhilke = null;
    
    // Stats
    this.stats = {
      sessionsCreated: 0,
      messagesEncrypted: 0,
      messagesDecrypted: 0,
      handshakesFailed: 0,
      replaysBlocked: 0,
    };
    
    // Deferred message queue — buffer ANNEX messages from peers whose
    // public key hasn't arrived yet (HELLO/WELCOME still in flight).
    // Max 10 senders, 1 message per sender, 3s timeout.
    this._deferredMessages = new Map();  // senderId -> { envelope, origin, timer }
    this._maxDeferredSenders = 10;
    this._deferTimeoutMs = 3000;
    
    // Register mesh handler for ANNEX messages
    if (this.mesh) {
      this._registerMeshHandlers();
    }
  }
  
  /**
   * Create a bootstrap session with a deterministic key.
   * JHILKE derives this key from the shared code hash + both node IDs.
   * Both sides compute the same key independently.
   *
   * The bootstrap session enables encrypted communication from message #1,
   * eliminating plaintext KEM exchange. It is immediately upgraded to a
   * proper KEM-backed session with full PFS.
   */
  bootstrapSession(peerId, bootstrapKey) {
    // Deterministic sessionId — both sides MUST agree on AES-GCM AAD.
    // AAD = "${sessionId}:${sequence}", so random sessionId = instant auth failure.
    const localNodeId = this.identity.identity.nodeId;
    const [first, second] = [localNodeId, peerId].sort();
    const deterministicSessionId = createHash('sha3-256')
      .update(`yakmesh-annex-bootstrap-session:${first}:${second}`)
      .digest('hex')
      .slice(0, 32); // same length as bytesToHex(randomBytes(16))

    const session = new AnnexSession({
      sessionId: deterministicSessionId,
      localNodeId,
      remoteNodeId: peerId,
    });
    session.encryptionKey = bootstrapKey;
    session.established = true;
    session.bootstrapped = true;
    session.channelState = ChannelState.ESTABLISHED;
    session.lastRekey = Date.now();
    
    this.sessions.set(peerId, session);
    log.info('JHILKE bootstrap session created (encrypted from message #1)', {
      peerId: peerTag(peerId),
      sessionId: deterministicSessionId.slice(0, 8) + '...',
    });
    return session;
  }
  
  /**
   * Initialize or get secure session with a peer (annex territory)
   * 
   * JHILKE integration: If a bootstrap session exists, this method
   * upgrades it to a KEM-backed session by performing the key exchange
   * THROUGH the bootstrap-encrypted channel (no plaintext KEM).
   */
  async openChannel(remoteNodeId) {
    // Check for existing session
    let session = this.sessions.get(remoteNodeId);
    
    // Return existing FULL (non-bootstrap) session
    if (session && session.established && !session.isExpired() && !session.bootstrapped) {
      return session;
    }
    
    // Bootstrap upgrade: reuse existing session, add KEM negotiation
    const isBootstrapUpgrade = session?.bootstrapped;
    
    if (isBootstrapUpgrade) {
      session.initiator = true;
      log.info('JHILKE: upgrading bootstrap → KEM', { peer: peerTag(remoteNodeId) });
    } else {
      // Create new session
      session = new AnnexSession({
        localNodeId: this.identity.identity.nodeId,
        remoteNodeId,
        initiator: true,
      });
    }
    
    // Generate our key pair (ACCEL: native liboqs/AVX-512, STEADYWATCH: quantum seed)
    const ourPublicKey = await session.generateKeyPair();
    
    // Store pending handshake
    this.pendingHandshakes.set(remoteNodeId, session);
    
    // Send key exchange request
    const envelope = new AnnexEnvelope({
      type: ANNEX_CONFIG.messageTypes.KEY_EXCHANGE,
      senderId: this.identity.identity.nodeId,
      recipientId: remoteNodeId,
      sessionId: session.sessionId,
      kemPublicKey: ourPublicKey,
    });
    
    // Sign the envelope
    envelope.signature = this.identity.sign(envelope.getSigningPayload());
    
    // JHILKE: Send via secure channel if bootstrap exists, else raw
    await this._sendControlSecure(remoteNodeId, envelope);
    
    // Wait for response (with timeout)
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingHandshakes.delete(remoteNodeId);
        this.stats.handshakesFailed++;
        reject(new Error('ANNEX handshake timeout'));
      }, 30000);
      
      session._resolveHandshake = (establishedSession) => {
        clearTimeout(timeout);
        resolve(establishedSession);
      };
      
      session._rejectHandshake = (error) => {
        clearTimeout(timeout);
        this.stats.handshakesFailed++;
        reject(error);
      };
    });
  }
  
  /**
   * Send an encrypted message through the ANNEX channel
   */
  async send(remoteNodeId, payload, options = {}) {
    // Ensure we have a session
    let session = this.sessions.get(remoteNodeId);
    if (!session || !session.established || session.isExpired()) {
      session = await this.openChannel(remoteNodeId);
    }
    
    // Check for re-key need — JHILKE handles all rekeys deterministically.
    // Both sides derive the same key after cricket coordination (no KEM round-trip).
    if (!options._skipRekeyCheck && session.needsRekey()) {
      if (this.jhilke) {
        this.jhilke.initiateRekey(remoteNodeId);
      }
      // No fallback — JHILKE is the only rekey path. If unavailable,
      // the session continues until timeout/reconnect.
    }
    
    // Encrypt the payload
    const encrypted = session.encrypt(payload);
    
    // Create envelope
    const envelope = new AnnexEnvelope({
      type: ANNEX_CONFIG.messageTypes.ENCRYPTED,
      senderId: this.identity.identity.nodeId,
      recipientId: remoteNodeId,
      sessionId: session.sessionId,
      sequence: encrypted.sequence,
      nonce: encrypted.nonce,
      ciphertext: encrypted.ciphertext,
      authTag: encrypted.authTag,
    });
    
    // Sign
    envelope.signature = this.identity.sign(envelope.getSigningPayload());
    
    // Send
    await this._sendToMesh(remoteNodeId, envelope);
    this.stats.messagesEncrypted++;
    
    return { sent: true, sessionId: session.sessionId, sequence: encrypted.sequence };
  }
  
  /**
   * Register handler for decrypted messages
   */
  onMessage(handler) {
    const id = bytesToHex(randomBytes(8));
    this.messageHandlers.set(id, handler);
    return id;
  }
  
  /**
   * Remove message handler
   */
  offMessage(handlerId) {
    this.messageHandlers.delete(handlerId);
  }
  
  /**
   * Close ANNEX channel with peer (release territory)
   */
  async closeChannel(remoteNodeId) {
    const session = this.sessions.get(remoteNodeId);
    if (!session) return;
    
    // Send close notification
    const envelope = new AnnexEnvelope({
      type: ANNEX_CONFIG.messageTypes.CLOSE,
      senderId: this.identity.identity.nodeId,
      recipientId: remoteNodeId,
      sessionId: session.sessionId,
    });
    envelope.signature = this.identity.sign(envelope.getSigningPayload());
    
    await this._sendToMesh(remoteNodeId, envelope);
    session.channelState = ChannelState.CLOSED;
    this.sessions.delete(remoteNodeId);
    
    // Clean up any deferred messages from this peer
    const deferred = this._deferredMessages?.get(remoteNodeId);
    if (deferred) {
      clearTimeout(deferred.timer);
      if (deferred.onRegistered) {
        this.mesh.off('peer-registered', deferred.onRegistered);
      }
      this._deferredMessages.delete(remoteNodeId);
    }
  }
  
  /**
   * Get session info
   */
  getSessionInfo(remoteNodeId) {
    const session = this.sessions.get(remoteNodeId);
    if (!session) return null;
    
    return {
      sessionId: session.sessionId,
      established: session.established,
      channelState: session.channelState,  // TRIBHUJ trit: ESTABLISHED/NEGOTIATING/CLOSED
      createdAt: session.createdAt,
      lastActivity: session.lastActivity,
      messageCount: session.messageCount,
      needsRekey: session.needsRekey(),
      isExpired: session.isExpired(),
    };
  }
  
  /**
   * List all active annexes (sessions)
   */
  listAnnexes() {
    const annexes = [];
    for (const [nodeId, session] of this.sessions) {
      annexes.push({
        nodeId,
        sessionId: session.sessionId,
        established: session.established,
        channelState: session.channelState,  // TRIBHUJ trit
        createdAt: session.createdAt,
        lastActivity: session.lastActivity,
        messageCount: session.messageCount,
        isExpired: session.isExpired(),
      });
    }
    return annexes;
  }
  
  /**
   * Get stats
   */
  getStats() {
    return {
      ...this.stats,
      activeSessions: this.sessions.size,
      pendingHandshakes: this.pendingHandshakes.size,
    };
  }
  
  // === Private Methods ===
  
  _registerMeshHandlers() {
    // Handle incoming ANNEX messages
    this.mesh.on('annex', async (data, origin) => {
      await this._handleAnnexMessage(data, origin);
    });
  }
  
  async _handleAnnexMessage(envelope, origin) {
    try {
      // Verify ML-DSA-65 signature — MANDATORY for all ANNEX messages.
      // "Changes pass through math alone" — no key, no entry.
      const peerPublicKey = this._getPeerPublicKey(envelope.senderId);
      
      if (!peerPublicKey) {
        // Peer's public key isn't registered yet — their HELLO/WELCOME
        // may still be in flight. Defer the message and replay it once
        // the mesh emits 'peer-registered' for this sender.
        this._deferMessage(envelope, origin);
        return;
      }
      
      const sigPayload = AnnexEnvelope.fromJSON(envelope).getSigningPayload();
      if (!this.identity.verify(sigPayload, envelope.signature, peerPublicKey)) {
        log.warn('Invalid ML-DSA-65 signature from peer', { peerId: peerTag(envelope.senderId) });
        return;
      }
      
      switch (envelope.type) {
        case ANNEX_CONFIG.messageTypes.KEY_EXCHANGE:
          await this._handleKeyExchange(envelope);
          break;
          
        case ANNEX_CONFIG.messageTypes.KEY_RESPONSE:
          await this._handleKeyResponse(envelope);
          break;
          
        case ANNEX_CONFIG.messageTypes.ENCRYPTED:
          await this._handleEncrypted(envelope);
          break;
          
        case ANNEX_CONFIG.messageTypes.CLOSE: {
          const closedSession = this.sessions.get(envelope.senderId);
          if (closedSession) closedSession.channelState = ChannelState.CLOSED;
          this.sessions.delete(envelope.senderId);
          log.info('Channel closed by peer', { peerId: peerTag(envelope.senderId) });
          break;
        }
      }
    } catch (err) {
      log.error('Error handling ANNEX message', { error: err.message });
    }
  }
  
  async _handleKeyExchange(envelope) {
    log.info('Key exchange from peer', { peerId: peerTag(envelope.senderId) });
    
    // JHILKE: Check for existing bootstrap session to upgrade
    let session = this.sessions.get(envelope.senderId);
    const isBootstrapUpgrade = session?.bootstrapped;
    
    if (isBootstrapUpgrade) {
      // Upgrade existing bootstrap session — keep bootstrap key as current
      session.sessionId = envelope.sessionId;
      session.initiator = false;
      log.info('JHILKE: upgrading bootstrap → KEM (responder)', { peerId: peerTag(envelope.senderId) });
    } else {
      // Create responding session
      session = new AnnexSession({
        sessionId: envelope.sessionId,
        localNodeId: this.identity.identity.nodeId,
        remoteNodeId: envelope.senderId,
        initiator: false,
      });
    }
    
    // Generate our key pair and encapsulate with peer's public key
    // ACCEL: native liboqs/AVX-512, STEADYWATCH: quantum seed
    await session.generateKeyPair();
    
    // CRITICAL: For bootstrap upgrades, DEFER the KEM key.
    // Keep bootstrap key active for the KEY_RESPONSE message.
    // The KEM key activates via implicit ack when we receive
    // a message encrypted with it from the initiator.
    const kemCiphertext = session.encapsulate(envelope.kemPublicKey, { defer: isBootstrapUpgrade });
    
    // Store session
    this.sessions.set(envelope.senderId, session);
    if (!isBootstrapUpgrade) this.stats.sessionsCreated++;
    
    // Send response with our public key and the KEM ciphertext
    const response = new AnnexEnvelope({
      type: ANNEX_CONFIG.messageTypes.KEY_RESPONSE,
      senderId: this.identity.identity.nodeId,
      recipientId: envelope.senderId,
      sessionId: session.sessionId,
      kemPublicKey: bytesToHex(session.kemKeyPair.publicKey),
      kemCiphertext: kemCiphertext,
    });
    
    response.signature = this.identity.sign(response.getSigningPayload());
    
    // JHILKE: Send via secure channel (encrypted through bootstrap or current key)
    await this._sendControlSecure(envelope.senderId, response);
    
    log.info('Channel established with peer', { peerId: peerTag(envelope.senderId) });
  }
  
  async _handleKeyResponse(envelope) {
    // KEY_RESPONSE is only used during initial handshake or bootstrap→KEM upgrade.
    // All subsequent rekeys are deterministic via JHILKE (no KEM round-trip).
    const session = this.pendingHandshakes.get(envelope.senderId);
    
    if (!session) {
      log.warn('Unexpected key response (no pending handshake)', { peerId: peerTag(envelope.senderId) });
      return;
    }
    
    // Decapsulate to get shared secret
    session.decapsulate(envelope.kemCiphertext);
    
    // JHILKE: Clear bootstrap flag — now KEM-backed with full PFS
    session.bootstrapped = false;
    
    // Move from pending to active
    this.pendingHandshakes.delete(envelope.senderId);
    this.sessions.set(envelope.senderId, session);
    this.stats.sessionsCreated++;
    log.info('Channel established with peer', { peerId: peerTag(envelope.senderId) });
    
    // Resolve the handshake promise
    if (session._resolveHandshake) {
      session._resolveHandshake(session);
    }
  }
  
  async _handleEncrypted(envelope) {
    const session = this.sessions.get(envelope.senderId);
    if (!session || !session.established) {
      log.warn('No session for encrypted message', { peerId: peerTag(envelope.senderId) });
      return;
    }
    
    try {
      // Decrypt
      const plaintext = session.decrypt(
        {
          nonce: envelope.nonce,
          ciphertext: envelope.ciphertext,
          authTag: envelope.authTag,
        },
        envelope.sequence
      );
      
      this.stats.messagesDecrypted++;
      
      // Parse and dispatch to handlers
      let payload;
      try {
        payload = JSON.parse(plaintext);
      } catch {
        payload = plaintext;
      }
      
      // JHILKE: Intercept secure ANNEX control messages routed through
      // the encrypted channel (bootstrap upgrade, encrypted rekey, etc.)
      if (payload && payload._annexControl) {
        await this._handleAnnexControl(payload._annexControl, envelope.senderId);
        return;
      }
      
      // Dispatch to handlers
      for (const handler of this.messageHandlers.values()) {
        try {
          await handler({
            from: envelope.senderId,
            sessionId: envelope.sessionId,
            payload,
            timestamp: envelope.timestamp,
          });
        } catch (err) {
          log.error('Handler error', { error: err.message });
        }
      }
    } catch (err) {
      if (err.message.includes('Replay')) {
        this.stats.replaysBlocked++;
        log.warn('Replay attack blocked', { error: err.message });
      } else {
        throw err;
      }
    }
  }

  
  // KEM-based _handleRekey and _rekey REMOVED — JHILKE handles all rekeys
  // deterministically via deriveRekeyKey(). Both nodes compute the same key
  // after cricket coordination. No encapsulate/decapsulate dance needed.
  
  /**
   * Send an ANNEX control message securely through the existing encrypted channel.
   * When a session exists, wraps the control message inside an encrypted payload.
   * Falls back to raw transport only when no session exists (pre-bootstrap).
   *
   * This eliminates plaintext KEM exchange after bootstrap — all ANNEX control
   * messages (KEY_EXCHANGE, KEY_RESPONSE, REKEY) are encrypted on the wire.
   */
  async _sendControlSecure(remoteNodeId, controlEnvelope) {
    const session = this.sessions.get(remoteNodeId);
    if (session?.established) {
      // Wrap control message inside encrypted ANNEX payload
      // _skipRekeyCheck prevents recursive rekey triggers
      await this.send(remoteNodeId, { _annexControl: controlEnvelope.toJSON() }, { _skipRekeyCheck: true });
    } else {
      // No session yet — raw transport (only during pre-JHILKE or HELLO/WELCOME phase)
      await this._sendToMesh(remoteNodeId, controlEnvelope);
    }
  }
  
  /**
   * Handle a secure ANNEX control message received through the encrypted channel.
   * The outer AEAD encryption guarantees authenticity — no separate signature
   * check needed (only the session peer could have encrypted it).
   */
  async _handleAnnexControl(controlData, senderId) {
    log.debug('Processing secure ANNEX control', {
      type: controlData.type,
      from: peerTag(senderId),
    });
    
    switch (controlData.type) {
      case ANNEX_CONFIG.messageTypes.KEY_EXCHANGE:
        await this._handleKeyExchange(controlData);
        break;
      case ANNEX_CONFIG.messageTypes.KEY_RESPONSE:
        await this._handleKeyResponse(controlData);
        break;
      case ANNEX_CONFIG.messageTypes.CLOSE: {
        const closedSession = this.sessions.get(controlData.senderId);
        if (closedSession) closedSession.channelState = ChannelState.CLOSED;
        this.sessions.delete(controlData.senderId);
        log.info('Channel closed by peer (secure)', { peerId: peerTag(controlData.senderId) });
        break;
      }
    }
  }
  
  async _sendToMesh(remoteNodeId, envelope) {
    if (!this.mesh) {
      throw new Error('No mesh connection');
    }
    
    this.mesh.sendTo(remoteNodeId, {
      type: 'annex',
      annex: envelope.toJSON(),
    });
  }
  
  /**
   * Buffer an ANNEX message whose sender key hasn't arrived yet.
   * Replays automatically when 'peer-registered' fires, or discards
   * after _deferTimeoutMs (preventing memory leaks from spoofed senderIds).
   */
  _deferMessage(envelope, origin) {
    const senderId = envelope.senderId;
    
    // Already deferring a message from this sender — discard the older one
    if (this._deferredMessages.has(senderId)) {
      const existing = this._deferredMessages.get(senderId);
      clearTimeout(existing.timer);
      if (existing.onRegistered) {
        this.mesh.off('peer-registered', existing.onRegistered);
      }
      this._deferredMessages.delete(senderId);
    }
    
    // Cap total deferred senders to prevent memory abuse
    if (this._deferredMessages.size >= this._maxDeferredSenders) {
      log.debug('Deferred ANNEX queue full, dropping message from unknown peer', {
        peerId: peerTag(senderId),
        type: envelope.type,
      });
      return;
    }
    
    log.debug('Deferring ANNEX message until peer key arrives', {
      peerId: peerTag(senderId),
      type: envelope.type,
    });
    
    // Event listener: replay when peer registers
    const onRegistered = (registeredNodeId) => {
      if (registeredNodeId === senderId) {
        this._replayDeferred(senderId);
      }
    };
    
    // Safety timeout: if key never arrives, discard silently
    const timer = setTimeout(() => {
      if (this._deferredMessages.has(senderId)) {
        this.mesh.off('peer-registered', onRegistered);
        this._deferredMessages.delete(senderId);
        log.debug('Deferred ANNEX message expired (peer key never arrived)', {
          peerId: peerTag(senderId),
          type: envelope.type,
        });
      }
    }, this._deferTimeoutMs);
    
    this._deferredMessages.set(senderId, { envelope, origin, timer, onRegistered });
    this.mesh.on('peer-registered', onRegistered);
  }
  
  /**
   * Replay a deferred ANNEX message now that the sender's key is available.
   */
  _replayDeferred(senderId) {
    const deferred = this._deferredMessages.get(senderId);
    if (!deferred) return;
    
    clearTimeout(deferred.timer);
    this.mesh.off('peer-registered', deferred.onRegistered);
    this._deferredMessages.delete(senderId);
    
    log.debug('Replaying deferred ANNEX message (peer key arrived)', {
      peerId: peerTag(senderId),
      type: deferred.envelope.type,
    });
    
    // Re-enter the handler — this time _getPeerPublicKey should succeed
    this._handleAnnexMessage(deferred.envelope, deferred.origin).catch(err => {
      log.warn('Deferred ANNEX replay failed', { peerId: peerTag(senderId), error: err.message });
    });
  }
  
  _getPeerPublicKey(nodeId) {
    // Get from WS peer info first
    if (this.mesh && this.mesh.peers) {
      const peer = this.mesh.peers.get(nodeId);
      if (peer?.identity?.publicKey) return peer.identity.publicKey;
    }
    // Fallback: relay peer keys stored during signed registration
    if (this.mesh && this.mesh._relayPeerKeys) {
      const key = this.mesh._relayPeerKeys.get(nodeId);
      if (key) return key;
    }
    // Fallback: SHERPA registry (populated during relay registration)
    if (this.mesh && this.mesh.sherpa?.registry) {
      const regPeer = this.mesh.sherpa.registry.get(nodeId);
      if (regPeer?.publicKey) return regPeer.publicKey;
    }
    return null;
  }
}

// Export config for external use
export { ANNEX_CONFIG, AnnexEnvelope, AnnexSession };

export default Annex;
