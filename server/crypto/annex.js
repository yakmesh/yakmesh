/**
 * Server-side ANNEX - Post-Quantum Encrypted Sessions
 * 
 * Handles ANNEX key exchange and message encryption/decryption for
 * browser clients connecting via WebSocket.
 * 
 * Protocol (server perspective):
 * 1. Receive client's ML-KEM-768 public key
 * 2. Encapsulate shared secret, send ciphertext to client
 * 3. Both derive AES-256-GCM key from shared secret
 * 4. All subsequent messages encrypted/decrypted via session
 * 
 * @module server/crypto/annex
 * @license MIT
 * @copyright 2026 YAKMESH Contributors
 */

import { randomBytes, createCipheriv, createDecipheriv, createHash } from 'crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// Configuration (must match client)
const ANNEX_CONFIG = {
  nonceSize: 12,
  keyDerivationSalt: 'YAKMESH-ANNEX-VANI-2026',
  sessionTimeout: 3600000,      // 1 hour session lifetime
  maxMessagesPerKey: 50000,     // Force re-handshake after N messages
};

/**
 * ServerAnnexSession - Server-side encrypted session with a browser client
 */
export class ServerAnnexSession {
  constructor(options = {}) {
    this.sessionId = options.sessionId;
    this.clientId = options.clientId || 'client';
    this.serverId = options.serverId || 'server';
    
    // Encryption key (derived from shared secret)
    this.encryptionKey = null;
    
    // Sequence counters for replay protection
    this.sendSequence = 0;
    this.recvSequence = 0;
    this.messageCount = 0;
    
    // State
    this.established = false;
    this.createdAt = Date.now();
    this.lastActivity = Date.now();
  }
  
  /**
   * Check if session has exceeded its lifetime or message limit
   */
  isExpired() {
    if (!this.established) return false;
    const age = Date.now() - this.createdAt;
    return age > ANNEX_CONFIG.sessionTimeout || 
           this.messageCount >= ANNEX_CONFIG.maxMessagesPerKey;
  }
  
  /**
   * Check if session is approaching expiry (80% of limits)
   * Used to trigger proactive rekey before hard expiry
   */
  isNearingExpiry() {
    if (!this.established) return false;
    const age = Date.now() - this.createdAt;
    return age > ANNEX_CONFIG.sessionTimeout * 0.8 || 
           this.messageCount >= ANNEX_CONFIG.maxMessagesPerKey * 0.8;
  }
  
  /**
   * Rekey the session with a new client public key.
   * Preserves the connection but rotates the encryption key.
   * Returns new ciphertext to send back to client.
   */
  async rekey(publicKeyHex) {
    const oldKey = this.encryptionKey;
    
    // Generate new shared secret from client's new public key
    const publicKey = hexToBytes(publicKeyHex);
    const { sharedSecret, cipherText } = ml_kem768.encapsulate(publicKey);
    
    // Derive fresh AES-256 key
    this.encryptionKey = this._deriveKey(sharedSecret);
    
    // Zero old key and shared secret
    if (oldKey?.fill) oldKey.fill(0);
    if (sharedSecret?.fill) sharedSecret.fill(0);
    
    // Reset counters but preserve session identity
    this.sendSequence = 0;
    this.recvSequence = 0;
    this.messageCount = 0;
    this.createdAt = Date.now();
    this.lastActivity = Date.now();
    
    console.log(`[ServerAnnex] Session ${this.sessionId} rekeyed successfully`);
    
    return bytesToHex(cipherText);
  }
  
  /**
   * Handle client's public key - encapsulate shared secret
   * Returns ciphertext to send back to client
   */
  async handlePublicKey(publicKeyHex) {
    const publicKey = hexToBytes(publicKeyHex);
    
    // Server encapsulates - generates random shared secret + ciphertext
    const { sharedSecret, cipherText } = ml_kem768.encapsulate(publicKey);
    
    // Derive AES-256 key from shared secret
    this.encryptionKey = this._deriveKey(sharedSecret);
    
    // Zero shared secret immediately — only the derived key is needed from here
    // sharedSecret is a Uint8Array from ml-kem768
    if (sharedSecret?.fill) sharedSecret.fill(0);
    
    this.established = true;
    
    console.log(`[ServerAnnex] Session ${this.sessionId} established with ${this.clientId}`);
    
    return bytesToHex(cipherText);
  }
  
  /**
   * Derive AES-256 key from shared secret using SHA3-256
   */
  _deriveKey(sharedSecret) {
    // Hash: sharedSecret + salt + sessionId + clientId + serverId
    const keyMaterial = Buffer.concat([
      Buffer.from(sharedSecret),
      Buffer.from(ANNEX_CONFIG.keyDerivationSalt),
      Buffer.from(this.sessionId),
      Buffer.from(this.clientId),  // Client is "local" from their perspective
      Buffer.from(this.serverId),   // Server is "remote" from their perspective
    ]);
    
    // Use SHA3-256 to derive 32-byte AES key
    const key = Buffer.from(sha3_256(keyMaterial));
    
    return key;
  }
  
  /**
   * Encrypt data for transmission to client
   * Returns { nonce, ciphertext, authTag, sequence } as hex strings
   */
  encrypt(plaintext) {
    if (!this.established || !this.encryptionKey) {
      throw new Error('Session not established');
    }
    
    const nonce = randomBytes(ANNEX_CONFIG.nonceSize);
    
    // Encode plaintext
    const data = typeof plaintext === 'string'
      ? Buffer.from(plaintext)
      : Buffer.from(JSON.stringify(plaintext));
    
    // AAD for GCM authentication
    const aadString = `${this.sessionId}:${this.sendSequence}`;
    
    // Create cipher with AAD
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, nonce);
    cipher.setAAD(Buffer.from(aadString));
    
    // Encrypt
    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    const sequence = this.sendSequence;
    this.sendSequence++;
    this.messageCount++;
    this.lastActivity = Date.now();
    
    return {
      nonce: bytesToHex(nonce),
      ciphertext: bytesToHex(ciphertext),
      authTag: bytesToHex(authTag),
      sequence,
    };
  }
  
  /**
   * Decrypt received data from client
   * Returns plaintext string (JSON)
   */
  decrypt(encryptedData) {
    if (!this.established || !this.encryptionKey) {
      throw new Error('Session not established');
    }
    
    const { nonce, ciphertext, authTag, sequence } = encryptedData;
    
    // Replay protection — reject any sequence not strictly greater than last received
    if (typeof sequence !== 'number' || sequence <= this.recvSequence) {
      throw new Error(`Replay detected: sequence ${sequence} <= ${this.recvSequence}`);
    }
    
    const nonceBuffer = Buffer.from(hexToBytes(nonce));
    const ciphertextBuffer = Buffer.from(hexToBytes(ciphertext));
    const authTagBuffer = Buffer.from(hexToBytes(authTag));
    
    // Create decipher with AAD
    const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey, nonceBuffer);
    decipher.setAAD(Buffer.from(`${this.sessionId}:${sequence}`));
    decipher.setAuthTag(authTagBuffer);
    
    // Decrypt
    const plaintext = Buffer.concat([decipher.update(ciphertextBuffer), decipher.final()]);
    
    this.recvSequence = sequence;
    this.messageCount++;
    this.lastActivity = Date.now();
    
    return plaintext.toString('utf8');
  }
  
  /**
   * Destroy session and zero keys
   */
  destroy() {
    if (this.encryptionKey) {
      this.encryptionKey.fill(0);
      this.encryptionKey = null;
    }
    this.established = false;
    console.log(`[ServerAnnex] Session ${this.sessionId} destroyed`);
  }
}

// Handshake message types (must match client)
export const ANNEX_HANDSHAKE_TYPE = {
  PUBLIC_KEY: 'annex:public_key',
  ENCAPSULATED: 'annex:encapsulated',
  ENCRYPTED: 'annex:encrypted',
  ERROR: 'annex:error',
  REKEY: 'annex:rekey',       // Server -> Client: session needs rekeying
  REKEY_ACK: 'annex:rekey_ack', // Client -> Server: new public key for rekey
};

export default ServerAnnexSession;
