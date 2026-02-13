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
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { createLogger } from '../utils/logger.js';

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
    this.pendingEncryptionKey = null; // Future key awaiting implicit ack (PFS-safe: forward-looking only)
    this.sendSequence = 0;       // Outbound message counter
    this.recvSequence = -1;      // Inbound message counter (-1 so first msg seq 0 passes)
    this.messageCount = 0;       // Total messages with current key
    
    // State
    this.established = false;
    this.createdAt = Date.now();
    this.lastActivity = Date.now();
    this.lastRekey = null;
  }
  
  /**
   * Generate ephemeral KEM key pair for this session
   */
  generateKeyPair() {
    const seed = randomBytes(64);
    this.kemKeyPair = ml_kem768.keygen(seed);
    return bytesToHex(this.kemKeyPair.publicKey);
  }
  
  /**
   * Complete key exchange as initiator (encapsulate with peer's public key)
   */
  encapsulate(peerPublicKey, { defer = false } = {}) {
    const publicKeyBytes = hexToBytes(peerPublicKey);
    const result = ml_kem768.encapsulate(publicKeyBytes);
    
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
    this.sharedSecret = ml_kem768.decapsulate(ciphertextBytes, this.kemKeyPair.secretKey);
    // Initiator receiving KEY_RESPONSE: switch immediately, zero old key.
    // The initiator is always "first mover" — its next message triggers
    // the responder to promote pendingEncryptionKey. Old key material
    // is never retained (PFS preserved).
    this.encryptionKey = this._deriveEncryptionKey();
    this.pendingEncryptionKey = null; // Clear any pending state
    this.established = true;
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
        const result = this._decryptWithKey(this.pendingEncryptionKey, encryptedData, expectedSequence);
        // Implicit ack: promote pending → current, zero old key
        this.encryptionKey = this.pendingEncryptionKey;
        this.pendingEncryptionKey = null;
        this.recvSequence = expectedSequence;
        this.lastActivity = Date.now();
        log.info('Rekey activated via implicit ack', { sessionId: this.sessionId?.slice(0, 16) });
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
    
    // Stats
    this.stats = {
      sessionsCreated: 0,
      messagesEncrypted: 0,
      messagesDecrypted: 0,
      handshakesFailed: 0,
      replaysBlocked: 0,
    };
    
    // Register mesh handler for ANNEX messages
    if (this.mesh) {
      this._registerMeshHandlers();
    }
  }
  
  /**
   * Initialize or get secure session with a peer (annex territory)
   */
  async openChannel(remoteNodeId) {
    // Check for existing session
    let session = this.sessions.get(remoteNodeId);
    if (session && session.established && !session.isExpired()) {
      return session;
    }
    
    // Create new session
    session = new AnnexSession({
      localNodeId: this.identity.identity.nodeId,
      remoteNodeId,
      initiator: true,
    });
    
    // Generate our key pair
    const ourPublicKey = session.generateKeyPair();
    
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
    
    // Send via mesh
    await this._sendToMesh(remoteNodeId, envelope);
    
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
    
    // Check for re-key need
    if (session.needsRekey()) {
      await this._rekey(session);
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
    this.sessions.delete(remoteNodeId);
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
      // Verify signature
      const sigPayload = AnnexEnvelope.fromJSON(envelope).getSigningPayload();
      const peerPublicKey = this._getPeerPublicKey(envelope.senderId);
      
      if (peerPublicKey && !this.identity.verify(sigPayload, envelope.signature, peerPublicKey)) {
        log.warn('Invalid signature from peer', { peerId: envelope.senderId?.slice(0, 16) });
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
          
        case ANNEX_CONFIG.messageTypes.REKEY:
          await this._handleRekey(envelope);
          break;
          
        case ANNEX_CONFIG.messageTypes.CLOSE:
          this.sessions.delete(envelope.senderId);
          log.info('Channel closed by peer', { peerId: envelope.senderId?.slice(0, 16) });
          break;
      }
    } catch (err) {
      log.error('Error handling ANNEX message', { error: err.message });
    }
  }
  
  async _handleKeyExchange(envelope) {
    log.info('Key exchange from peer', { peerId: envelope.senderId?.slice(0, 16) });
    
    // Create responding session
    const session = new AnnexSession({
      sessionId: envelope.sessionId,
      localNodeId: this.identity.identity.nodeId,
      remoteNodeId: envelope.senderId,
      initiator: false,
    });
    
    // Generate our key pair and encapsulate with peer's public key
    session.generateKeyPair();
    const kemCiphertext = session.encapsulate(envelope.kemPublicKey);
    
    // Store session
    this.sessions.set(envelope.senderId, session);
    this.stats.sessionsCreated++;
    
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
    await this._sendToMesh(envelope.senderId, response);
    
    log.info('Channel established with peer', { peerId: envelope.senderId?.slice(0, 16) });
  }
  
  async _handleKeyResponse(envelope) {
    // Check pending handshakes first (initial key exchange)
    let session = this.pendingHandshakes.get(envelope.senderId);
    let isRekey = false;
    
    if (!session) {
      // Check active sessions — this is a rekey response
      session = this.sessions.get(envelope.senderId);
      if (!session || !session.established) {
        log.warn('Unexpected key response', { peerId: envelope.senderId?.slice(0, 16) });
        return;
      }
      isRekey = true;
    }
    
    // Decapsulate to get shared secret (saves previous key internally)
    session.decapsulate(envelope.kemCiphertext);
    
    if (isRekey) {
      session.messageCount = 0;
      log.info('Rekey completed with peer', { peerId: envelope.senderId?.slice(0, 16) });
    } else {
      // Move from pending to active
      this.pendingHandshakes.delete(envelope.senderId);
      this.sessions.set(envelope.senderId, session);
      this.stats.sessionsCreated++;
      log.info('Channel established with peer', { peerId: envelope.senderId?.slice(0, 16) });
    }
    
    // Resolve the handshake promise
    if (session._resolveHandshake) {
      session._resolveHandshake(session);
    }
  }
  
  async _handleEncrypted(envelope) {
    const session = this.sessions.get(envelope.senderId);
    if (!session || !session.established) {
      log.warn('No session for encrypted message', { peerId: envelope.senderId?.slice(0, 16) });
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
  
  async _handleRekey(envelope) {
    const session = this.sessions.get(envelope.senderId);
    if (!session) return;
    
    log.debug('Re-keying with peer', { peerId: envelope.senderId?.slice(0, 16) });
    
    // Respond to re-key: compute new key but DEFER activation.
    // The responder keeps encrypting with the current key until it receives
    // a message from the initiator encrypted with the new key (implicit ack
    // in decrypt()). This avoids storing the old key — only the future key
    // is held as pendingEncryptionKey, preserving PFS.
    session.generateKeyPair();
    const kemCiphertext = session.encapsulate(envelope.kemPublicKey, { defer: true });
    session.messageCount = 0;
    
    const response = new AnnexEnvelope({
      type: ANNEX_CONFIG.messageTypes.KEY_RESPONSE,
      senderId: this.identity.identity.nodeId,
      recipientId: envelope.senderId,
      sessionId: session.sessionId,
      kemPublicKey: bytesToHex(session.kemKeyPair.publicKey),
      kemCiphertext,
    });
    
    response.signature = this.identity.sign(response.getSigningPayload());
    await this._sendToMesh(envelope.senderId, response);
  }
  
  async _rekey(session) {
    log.debug('Initiating re-key with peer', { peerId: session.remoteNodeId?.slice(0, 16) });
    
    // Generate new ephemeral keys
    const newPublicKey = session.generateKeyPair();
    session.messageCount = 0;
    
    const envelope = new AnnexEnvelope({
      type: ANNEX_CONFIG.messageTypes.REKEY,
      senderId: this.identity.identity.nodeId,
      recipientId: session.remoteNodeId,
      sessionId: session.sessionId,
      kemPublicKey: newPublicKey,
    });
    
    envelope.signature = this.identity.sign(envelope.getSigningPayload());
    await this._sendToMesh(session.remoteNodeId, envelope);
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
  
  _getPeerPublicKey(nodeId) {
    // Get from mesh peer info
    if (this.mesh && this.mesh.peers) {
      const peer = this.mesh.peers.get(nodeId);
      return peer?.identity?.publicKey || null;
    }
    return null;
  }
}

// Export config for external use
export { ANNEX_CONFIG, AnnexEnvelope, AnnexSession };

export default Annex;
