/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0. If a copy of that
 * license agreement was not distributed with this file, You can
 * find a link to the license at https://yakmesh.dev/license
 *
 * This Source Code Form is "Incompatible With Secondary Licenses",
 * as defined by the YAKMESH NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
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
 * @license YakMesh-NE-1.0 (YAKMESH NETWORK ENGINE LICENSE AGREEMENT v1.0)
 * @copyright 2026 YAKMESH Contributors
 */

import { randomBytes, createCipheriv, createDecipheriv, createHash } from 'crypto';
import { mlKem768Encapsulate, sha3_256 } from '../../utils/accel.js';
import { aesGcm, aesGcmVerify } from '../../utils/mkc.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

// Configuration (must match client)
const ANNEX_CONFIG = {
  nonceSize: 12,
  keyDerivationSalt: 'YAKMESH-ANNEX-VANI-2026',
  sessionTimeout: 3600000,      // 1 hour session lifetime
  maxMessagesPerKey: 50000,     // Force re-handshake after N messages
};

/**
 * MKC bridge preference: AES-256-GCM runs on-silicon via the pq-bridge
 * (:9995) whenever reachable — node:crypto (AES-NI) is the fallback only.
 * Honest-device rule: a refused/unreachable bridge yields null, never a
 * faked device claim.
 */
let _mkcDownUntil = 0;
async function tryMkc(work) {
  if (Date.now() < _mkcDownUntil) return null;
  try {
    return await work();
  } catch {
    _mkcDownUntil = Date.now() + 60000; // retry the bridge after cooldown
    return null;
  }
}

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
    this.recvSequence = -1; // first valid client sequence is 0
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
    const { sharedSecret, cipherText } = mlKem768Encapsulate(publicKey);
    
    // Derive fresh AES-256 key
    this.encryptionKey = this._deriveKey(sharedSecret);
    
    // Zero old key and shared secret
    if (oldKey?.fill) oldKey.fill(0);
    if (sharedSecret?.fill) sharedSecret.fill(0);
    
    // Reset counters but preserve session identity
    this.sendSequence = 0;
    this.recvSequence = -1;
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
    const { sharedSecret, cipherText } = mlKem768Encapsulate(publicKey);
    
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
   * AES-GCM prefers the MKC silicon path; encrypts are chained so
   * sequence order is preserved across concurrent callers (the
   * receiver's replay guard requires strictly increasing sequences).
   */
  encrypt(plaintext) {
    if (!this.established || !this.encryptionKey) {
      throw new Error('Session not established');
    }

    const nonce = randomBytes(ANNEX_CONFIG.nonceSize);
    const data = typeof plaintext === 'string'
      ? Buffer.from(plaintext)
      : Buffer.from(JSON.stringify(plaintext));
    const aadString = `${this.sessionId}:${this.sendSequence}`;
    const sequence = this.sendSequence;
    this.sendSequence++;
    this.messageCount++;
    this.lastActivity = Date.now();

    const work = async () => {
      const sealed = await tryMkc(() =>
        aesGcm(this.encryptionKey, nonce, data, utf8ToBytes(aadString)));
      if (sealed) {
        return { ciphertext: Buffer.from(sealed.ct), authTag: Buffer.from(sealed.tag) };
      }
      const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, nonce);
      cipher.setAAD(Buffer.from(aadString));
      return {
        ciphertext: Buffer.concat([cipher.update(data), cipher.final()]),
        authTag: cipher.getAuthTag(),
      };
    };

    this._encChain = (this._encChain || Promise.resolve()).then(work);
    return this._encChain.then(({ ciphertext, authTag }) => ({
      nonce: bytesToHex(nonce),
      ciphertext: bytesToHex(ciphertext),
      authTag: bytesToHex(authTag),
      sequence,
    }));
  }
  
  /**
   * Decrypt received data from client
   * Returns plaintext string (JSON)
   */
  async decrypt(encryptedData) {
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
    const aadString = `${this.sessionId}:${sequence}`;
    
    let plaintext;
    const opened = await tryMkc(() =>
      aesGcmVerify(this.encryptionKey, nonceBuffer, ciphertextBuffer,
                   authTagBuffer, utf8ToBytes(aadString)));
    if (opened) {
      if (!opened.ok) throw new Error('GCM tag verification failed');
      plaintext = Buffer.from(opened.pt);
    } else {
      const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey, nonceBuffer);
      decipher.setAAD(Buffer.from(aadString));
      decipher.setAuthTag(authTagBuffer);
      plaintext = Buffer.concat([decipher.update(ciphertextBuffer), decipher.final()]);
    }
    
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
  REKEYED: 'annex:rekeyed',   // Server -> Client: new encapsulation ciphertext
};

export default ServerAnnexSession;
