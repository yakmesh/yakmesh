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
 * Client-side ANNEX - Post-Quantum Encrypted Sessions
 *
 * Browser/Node mirror of server/crypto/annex.js (ServerAnnexSession).
 * Pure-JS crypto (@noble) — works on http:// LAN dashboards where
 * WebCrypto's subtle API is unavailable (non-secure contexts).
 *
 * Protocol (client perspective):
 * 1. Generate ML-KEM-768 keypair, send public key
 * 2. Receive server's encapsulation ciphertext, decapsulate shared secret
 * 3. Both derive AES-256-GCM key via SHA3-256 (same material order)
 * 4. All subsequent messages encrypted/decrypted via session
 *
 * Bundled to public/js/annex-client.js (IIFE, window.AnnexClient) via esbuild.
 *
 * @module server/crypto/annex-client
 * @license YakMesh-NE-1.0 (YAKMESH NETWORK ENGINE LICENSE AGREEMENT v1.0)
 * @copyright 2026 YAKMESH Contributors
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { gcm } from '@noble/ciphers/aes.js';
import {
  bytesToHex,
  hexToBytes,
  concatBytes,
  utf8ToBytes,
  randomBytes,
} from '@noble/hashes/utils.js';

// Must match server/crypto/annex.js
const ANNEX_CONFIG = {
  nonceSize: 12,
  authTagSize: 16,
  keyDerivationSalt: 'YAKMESH-ANNEX-VANI-2026',
  sessionTimeout: 3600000,
};

// Must match server/crypto/annex.js
export const ANNEX_HANDSHAKE_TYPE = {
  PUBLIC_KEY: 'annex:public_key',
  ENCAPSULATED: 'annex:encapsulated',
  ENCRYPTED: 'annex:encrypted',
  ERROR: 'annex:error',
  REKEY: 'annex:rekey',
  REKEY_ACK: 'annex:rekey_ack',
  REKEYED: 'annex:rekeyed',
};

/**
 * AnnexClientSession - client half of a KOMM ANNEX channel.
 *
 * Usage:
 *   const session = new AnnexClientSession({ clientId: 'dashboard' });
 *   ws.send(JSON.stringify(session.handshake()));
 *   // on 'annex:encapsulated' msg:
 *   session.handleEncapsulated(msg);
 *   // thereafter:
 *   ws.send(session.encryptMessage({ type: 'dashboard:subscribe' }));
 *   const plain = session.decrypt(msg.payload); // on 'annex:encrypted'
 */
export class AnnexClientSession {
  constructor(options = {}) {
    this.sessionId = options.sessionId || `annex-${bytesToHex(randomBytes(8))}`;
    this.clientId = options.clientId || 'komm-client';
    this.serverId = null;

    this._publicKey = null;
    this._secretKey = null;
    this._encryptionKey = null;

    this.sendSequence = 0;
    this.recvSequence = -1;
    this.established = false;
    this.createdAt = Date.now();
  }

  isExpired() {
    return this.established &&
      (Date.now() - this.createdAt) > ANNEX_CONFIG.sessionTimeout;
  }

  /**
   * Generate a fresh ML-KEM-768 keypair.
   * Returns the PUBLIC_KEY handshake message to send.
   */
  handshake() {
    const { publicKey, secretKey } = ml_kem768.keygen();
    if (this._secretKey) this._secretKey.fill(0);
    this._publicKey = publicKey;
    this._secretKey = secretKey;
    return {
      type: ANNEX_HANDSHAKE_TYPE.PUBLIC_KEY,
      publicKey: bytesToHex(publicKey),
      clientId: this.clientId,
      sessionId: this.sessionId,
    };
  }

  /**
   * Decapsulate the server's ciphertext (annex:encapsulated / annex:rekeyed),
   * derive the AES-256-GCM session key, zero the KEM secret key.
   */
  handleEncapsulated(msg) {
    if (!this._secretKey) {
      throw new Error('No pending keypair — handshake() must be called first');
    }
    const shared = ml_kem768.decapsulate(hexToBytes(msg.ciphertext), this._secretKey);
    this._secretKey.fill(0);
    this._secretKey = null;
    if (msg.serverId) this.serverId = msg.serverId; // REKEYED replies omit it
    this._encryptionKey = this._deriveKey(shared);
    shared.fill(0);
    this.established = true;
    this.sendSequence = 0;
    this.recvSequence = -1;
    this.createdAt = Date.now();
    return true;
  }

  /** Alias for rekey completion — server's annex:rekeyed carries ciphertext. */
  handleRekeyed(msg) {
    return this.handleEncapsulated(msg);
  }

  /**
   * Respond to a server 'annex:rekey' request — fresh keypair, REKEY_ACK.
   */
  rekeyAck() {
    return { ...this.handshake(), type: ANNEX_HANDSHAKE_TYPE.REKEY_ACK };
  }

  /**
   * Derive AES-256 key from shared secret using SHA3-256.
   * MUST mirror ServerAnnexSession._deriveKey byte-for-byte:
   *   sharedSecret + salt + sessionId + clientId + serverId
   * where clientId is what the client sent and serverId is the server's
   * node tag (arrives in the ENCAPSULATED reply).
   */
  _deriveKey(sharedSecret) {
    return sha3_256(concatBytes(
      sharedSecret,
      utf8ToBytes(ANNEX_CONFIG.keyDerivationSalt),
      utf8ToBytes(this.sessionId),
      utf8ToBytes(this.clientId),
      utf8ToBytes(this.serverId),
    ));
  }

  /**
   * Encrypt a plaintext string for the server.
   * WebCrypto appends the GCM tag; the wire format carries it separately,
   * matching Node's cipher.getAuthTag().
   */
  encrypt(plaintext) {
    if (!this.established || !this._encryptionKey) {
      throw new Error('ANNEX session not established');
    }
    const nonce = randomBytes(ANNEX_CONFIG.nonceSize);
    const aad = utf8ToBytes(`${this.sessionId}:${this.sendSequence}`);
    const sealed = gcm(this._encryptionKey, nonce, aad)
      .encrypt(utf8ToBytes(plaintext));
    const split = sealed.length - ANNEX_CONFIG.authTagSize;
    const sequence = this.sendSequence++;
    return {
      nonce: bytesToHex(nonce),
      ciphertext: bytesToHex(sealed.slice(0, split)),
      authTag: bytesToHex(sealed.slice(split)),
      sequence,
    };
  }

  /**
   * Encrypt a JS object → the full WS message to send
   * ({ type: 'annex:encrypted', payload: {...} }).
   */
  encryptMessage(obj) {
    return JSON.stringify({
      type: ANNEX_HANDSHAKE_TYPE.ENCRYPTED,
      payload: this.encrypt(JSON.stringify(obj)),
    });
  }

  /**
   * Decrypt a server payload ({nonce,ciphertext,authTag,sequence} as hex)
   * → plaintext string. Rejects replays (sequence must strictly increase).
   */
  decrypt(payload) {
    if (!this.established || !this._encryptionKey) {
      throw new Error('ANNEX session not established');
    }
    const { nonce, ciphertext, authTag, sequence } = payload;
    if (typeof sequence !== 'number' || sequence <= this.recvSequence) {
      throw new Error(`ANNEX replay: sequence ${sequence} <= ${this.recvSequence}`);
    }
    const sealed = concatBytes(hexToBytes(ciphertext), hexToBytes(authTag));
    const aad = utf8ToBytes(`${this.sessionId}:${sequence}`);
    const plain = gcm(this._encryptionKey, hexToBytes(nonce), aad).decrypt(sealed);
    this.recvSequence = sequence;
    return new TextDecoder().decode(plain);
  }

  /** Zero all key material. */
  destroy() {
    if (this._encryptionKey) { this._encryptionKey.fill(0); this._encryptionKey = null; }
    if (this._secretKey) { this._secretKey.fill(0); this._secretKey = null; }
    this.established = false;
  }
}

export default AnnexClientSession;
