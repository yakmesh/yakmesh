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
 * Replay Attack Protection Module
 * @module mesh/replay-defense.js
 */

import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';

export class NonceRegistry {
  constructor(options = {}) {
    this.maxAge = options.maxAge || 3600000;
    this.maxSize = options.maxSize || 100000;
    this.nonces = new Map();
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
  }

  generate() {
    const nonce = bytesToHex(randomBytes(32));
    this.nonces.set(nonce, Date.now());
    return nonce;
  }

  validate(nonce) {
    if (!nonce || typeof nonce !== 'string') return { valid: false, reason: 'Missing or invalid nonce' };
    if (nonce.length !== 64) return { valid: false, reason: 'Invalid nonce length' };
    if (this.nonces.has(nonce)) return { valid: false, reason: 'Nonce already used (replay detected)' };
    this.nonces.set(nonce, Date.now());
    if (this.nonces.size > this.maxSize) this.cleanup();
    return { valid: true };
  }

  cleanup() {
    const cutoff = Date.now() - this.maxAge;
    for (const [nonce, ts] of this.nonces) { if (ts < cutoff) this.nonces.delete(nonce); }
  }

  getStats() { return { trackedNonces: this.nonces.size, maxSize: this.maxSize }; }
  destroy() { clearInterval(this.cleanupInterval); }
}

export class TimestampValidator {
  constructor(options = {}) {
    this.maxAge = options.maxAge || 600000;
    this.maxFuture = options.maxFuture || 60000;
  }

  validate(messageTime) {
    if (!messageTime || typeof messageTime !== 'number') return { valid: false, reason: 'Missing or invalid timestamp' };
    const drift = Date.now() - messageTime;
    if (drift > this.maxAge) return { valid: false, reason: 'Message too old (' + Math.round(drift/1000) + 's)', drift };
    if (drift < -this.maxFuture) return { valid: false, reason: 'Message from future', drift };
    return { valid: true, drift };
  }

  create() { return Date.now(); }
}

export class SequenceTracker {
  constructor(options = {}) {
    this.maxSenders = options.maxSenders || 10000;
    this.senders = new Map();
    this.windowSize = options.windowSize || 64;
    this.cleanupInterval = setInterval(() => this.cleanup(), 300000);
  }

  validate(senderId, seq) {
    if (!senderId) return { valid: false, reason: 'Missing sender ID' };
    if (typeof seq !== 'number' || seq < 0) return { valid: false, reason: 'Invalid sequence number' };

    let sender = this.senders.get(senderId);
    if (!sender) {
      sender = { lastSeq: seq, lastSeen: Date.now(), window: new Set([seq]) };
      this.senders.set(senderId, sender);
      return { valid: true, isNew: true };
    }

    sender.lastSeen = Date.now();
    if (sender.window.has(seq)) return { valid: false, reason: 'Duplicate sequence (replay)' };
    if (seq < sender.lastSeq - this.windowSize) return { valid: false, reason: 'Sequence too old' };

    sender.window.add(seq);
    if (seq > sender.lastSeq) sender.lastSeq = seq;
    if (sender.window.size > this.windowSize * 2) {
      const minSeq = sender.lastSeq - this.windowSize;
      for (const s of sender.window) { if (s < minSeq) sender.window.delete(s); }
    }
    return { valid: true };
  }

  nextSequence(peerId) {
    let sender = this.senders.get(peerId);
    if (!sender) { sender = { lastSeq: 0, lastSeen: Date.now(), window: new Set() }; this.senders.set(peerId, sender); }
    return ++sender.lastSeq;
  }

  cleanup() {
    const staleTime = 86400000;
    for (const [id, s] of this.senders) { if (Date.now() - s.lastSeen > staleTime) this.senders.delete(id); }
  }

  getStats() { return { trackedSenders: this.senders.size }; }
  destroy() { clearInterval(this.cleanupInterval); }
}

export class ReplayDefense {
  constructor(options = {}) {
    this.nonces = new NonceRegistry(options.nonces || {});
    this.timestamps = new TimestampValidator(options.timestamps || {});
    this.sequences = new SequenceTracker(options.sequences || {});
  }

  validateMessage(message) {
    const details = {};
    const timeCheck = this.timestamps.validate(message.timestamp);
    details.timestamp = timeCheck;
    if (!timeCheck.valid) return { valid: false, reason: timeCheck.reason, details };

    const nonceCheck = this.nonces.validate(message.nonce);
    details.nonce = nonceCheck;
    if (!nonceCheck.valid) return { valid: false, reason: nonceCheck.reason, details };

    if (message.senderId && message.seq !== undefined) {
      const seqCheck = this.sequences.validate(message.senderId, message.seq);
      details.sequence = seqCheck;
      if (!seqCheck.valid) return { valid: false, reason: seqCheck.reason, details };
    }
    return { valid: true, details };
  }

  prepareMessage(senderId, peerId) {
    return { nonce: this.nonces.generate(), timestamp: this.timestamps.create(), seq: this.sequences.nextSequence(peerId || 'broadcast') };
  }

  getStats() { return { nonces: this.nonces.getStats(), sequences: this.sequences.getStats() }; }

  destroy() { this.nonces.destroy(); this.sequences.destroy(); }
}

export default ReplayDefense;
