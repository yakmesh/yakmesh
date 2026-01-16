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
    this.sendSequence = 0;       // Outbound message counter
    this.recvSequence = 0;       // Inbound message counter
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
  encapsulate(peerPublicKey) {
    const publicKeyBytes = hexToBytes(peerPublicKey);
    const result = ml_kem768.encapsulate(publicKeyBytes);
    
    this.sharedSecret = result.sharedSecret;
    this.encryptionKey = this._deriveEncryptionKey();
    this.established = true;
    this.lastRekey = Date.now();
    
    return bytesToHex(result.ciphertext);
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
    this.encryptionKey = this._deriveEncryptionKey();
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
  decrypt(encryptedData, expectedSequence) {
    if (!this.established || !this.encryptionKey) {
      throw new Error('Session not established');
    }
    
    // Replay protection: sequence must be greater than last received
    if (expectedSequence <= this.recvSequence && this.recvSequence > 0) {
      throw new Error(`Replay detected: sequence ${expectedSequence} <= ${this.recvSequence}`);
    }
    
    const nonce = Buffer.from(encryptedData.nonce, 'hex');
    const ciphertext = Buffer.from(encryptedData.ciphertext, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    
    const decipher = createDecipheriv(
      ANNEX_CONFIG.symmetricAlgorithm,
      this.encryptionKey,
      nonce,
      { authTagLength: ANNEX_CONFIG.authTagLength }
    );
    
    // Verify AAD
    const aad = Buffer.from(`${this.sessionId}:${expectedSequence}`);
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    
    this.recvSequence = expectedSequence;
    this.lastActivity = Date.now();
    
    return decrypted.toString('utf8');
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
    return createHash('sha256')
      .update(this.sharedSecret)
      .update(ANNEX_CONFIG.keyDerivationSalt)
      .update(this.sessionId)
      .update(this.localNodeId)
      .update(this.remoteNodeId)
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
        console.warn(`⚠️ ANNEX: Invalid signature from ${envelope.senderId?.slice(0, 16)}...`);
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
          console.log(`🏳️ ANNEX: Channel closed by ${envelope.senderId?.slice(0, 16)}...`);
          break;
      }
    } catch (err) {
      console.error('ANNEX error:', err.message);
    }
  }
  
  async _handleKeyExchange(envelope) {
    console.log(`🤝 ANNEX: Key exchange from ${envelope.senderId?.slice(0, 16)}...`);
    
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
    
    console.log(`🔐 ANNEX: Channel established with ${envelope.senderId?.slice(0, 16)}...`);
  }
  
  async _handleKeyResponse(envelope) {
    const session = this.pendingHandshakes.get(envelope.senderId);
    if (!session) {
      console.warn('ANNEX: Unexpected key response');
      return;
    }
    
    // Decapsulate to get shared secret
    session.decapsulate(envelope.kemCiphertext);
    
    // Move to active sessions
    this.pendingHandshakes.delete(envelope.senderId);
    this.sessions.set(envelope.senderId, session);
    this.stats.sessionsCreated++;
    
    console.log(`🔐 ANNEX: Channel established with ${envelope.senderId?.slice(0, 16)}...`);
    
    // Resolve the handshake promise
    if (session._resolveHandshake) {
      session._resolveHandshake(session);
    }
  }
  
  async _handleEncrypted(envelope) {
    const session = this.sessions.get(envelope.senderId);
    if (!session || !session.established) {
      console.warn('ANNEX: No session for encrypted message');
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
          console.error('ANNEX handler error:', err.message);
        }
      }
    } catch (err) {
      if (err.message.includes('Replay')) {
        this.stats.replaysBlocked++;
        console.warn(`⚠️ ANNEX: ${err.message}`);
      } else {
        throw err;
      }
    }
  }
  
  async _handleRekey(envelope) {
    const session = this.sessions.get(envelope.senderId);
    if (!session) return;
    
    console.log(`🔄 ANNEX: Re-keying with ${envelope.senderId?.slice(0, 16)}...`);
    
    // Respond to re-key with new key exchange
    session.generateKeyPair();
    const kemCiphertext = session.encapsulate(envelope.kemPublicKey);
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
    console.log(`🔄 ANNEX: Initiating re-key with ${session.remoteNodeId?.slice(0, 16)}...`);
    
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
