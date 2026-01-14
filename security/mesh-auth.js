/**
 * Yakmesh Pro - Security Module
 * 
 * WebSocket authentication and message encryption for private networks.
 * 
 * @module security/mesh-auth
 * @version 1.0.0
 * @license Proprietary (Yakmesh Pro)
 */

import { sha3_256 } from '@noble/hashes/sha3';
import { randomBytes, bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { EventEmitter } from 'events';

const AUTH_CHALLENGE_TIMEOUT = 30000;
const AUTH_NONCE_SIZE = 24;

export class MeshAuthenticator extends EventEmitter {
  constructor(nodeIdentity, options = {}) {
    super();
    this.identity = nodeIdentity;
    this.options = {
      requireAuth: options.requireAuth ?? false,
      allowlist: new Set(options.allowlist || []),
      blocklist: new Set(options.blocklist || []),
      maxPendingAuth: options.maxPendingAuth || 100,
      challengeTimeout: options.challengeTimeout || AUTH_CHALLENGE_TIMEOUT,
    };
    this.pendingChallenges = new Map();
    this.sessions = new Map();
    this.stats = { authAttempts: 0, authSuccess: 0, authFailed: 0, blocked: 0 };
  }
  
  isAllowed(peerId) {
    if (this.options.blocklist.has(peerId)) {
      this.stats.blocked++;
      return false;
    }
    if (this.options.allowlist.size === 0) return true;
    return this.options.allowlist.has(peerId);
  }
  
  generateChallenge(peerId) {
    if (this.pendingChallenges.size >= this.options.maxPendingAuth) {
      throw new Error('Too many pending authentication requests');
    }
    const challenge = {
      type: 'auth_challenge',
      challengeId: bytesToHex(randomBytes(16)),
      nonce: bytesToHex(randomBytes(32)),
      timestamp: Date.now(),
      challengerNodeId: this.identity.identity.nodeId,
    };
    this.pendingChallenges.set(challenge.challengeId, { peerId, challenge, createdAt: Date.now() });
    setTimeout(() => this.pendingChallenges.delete(challenge.challengeId), this.options.challengeTimeout);
    this.stats.authAttempts++;
    return challenge;
  }
  
  respondToChallenge(challenge) {
    const responseData = JSON.stringify({
      challengeId: challenge.challengeId,
      nonce: challenge.nonce,
      responderNodeId: this.identity.identity.nodeId,
      timestamp: Date.now(),
    });
    const signature = this.identity.sign(responseData);
    return {
      type: 'auth_response',
      challengeId: challenge.challengeId,
      responderNodeId: this.identity.identity.nodeId,
      responderPublicKey: this.identity.identity.publicKey,
      responseData,
      signature,
    };
  }
  
  verifyResponse(response) {
    const pending = this.pendingChallenges.get(response.challengeId);
    if (!pending) {
      this.stats.authFailed++;
      return { valid: false, error: 'Unknown or expired challenge' };
    }
    const isValid = this.identity.verify(response.responseData, response.signature, response.responderPublicKey);
    if (!isValid) {
      this.stats.authFailed++;
      this.pendingChallenges.delete(response.challengeId);
      return { valid: false, error: 'Invalid signature' };
    }
    if (!this.isAllowed(response.responderNodeId)) {
      this.stats.authFailed++;
      return { valid: false, error: 'Peer not allowed' };
    }
    this.pendingChallenges.delete(response.challengeId);
    this.stats.authSuccess++;
    const sessionKey = this._deriveSessionKey(response.responderNodeId, pending.challenge.nonce);
    this.sessions.set(response.responderNodeId, {
      publicKey: response.responderPublicKey,
      sessionKey,
      authenticatedAt: Date.now(),
    });
    this.emit('authenticated', { peerId: response.responderNodeId });
    return { valid: true, peerId: response.responderNodeId, sessionKey: bytesToHex(sessionKey) };
  }
  
  isAuthenticated(peerId) { return this.sessions.has(peerId); }
  getSession(peerId) { return this.sessions.get(peerId) || null; }
  revokeSession(peerId) { this.sessions.delete(peerId); this.emit('session-revoked', { peerId }); }
  block(peerId) { this.options.blocklist.add(peerId); this.revokeSession(peerId); }
  unblock(peerId) { this.options.blocklist.delete(peerId); }
  
  _deriveSessionKey(peerId, nonce) {
    return sha3_256(utf8ToBytes(peerId + nonce + this.identity.identity.nodeId));
  }
  
  getStats() {
    return { ...this.stats, pendingChallenges: this.pendingChallenges.size, activeSessions: this.sessions.size };
  }
}

export default { MeshAuthenticator };


