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
 * Sybil Attack Protection Module
 * 
 * Uses TRIBHUJ balanced ternary for connection evaluation:
 *   POSITIVE (+1): Accept — node is trusted or verified
 *   NEUTRAL  ( 0): Challenge — node must prove itself (NAVR required)
 *   NEGATIVE (-1): Reject — node is banned or subnet saturated
 * 
 * @module mesh/sybil-defense.js
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

// ═══ TRIBHUJ — Balanced ternary for connection decisions ═══
import { POSITIVE, NEUTRAL, NEGATIVE } from '../oracle/tribhuj.js';

export class NAVR {
  constructor(options = {}) {
    this.difficulty = options.difficulty || 16;
    this.maxAttempts = options.maxAttempts || 10_000_000;
  }

  createChallenge(nodeId, timestamp = Date.now()) {
    const epochHour = Math.floor(timestamp / 3600000);
    const challenge = bytesToHex(sha3_256(utf8ToBytes(nodeId + ':' + epochHour)));
    return { nodeId, challenge, epochHour, difficulty: this.difficulty, expiresAt: (epochHour + 1) * 3600000 };
  }

  solve(challenge) {
    const target = BigInt(2) ** BigInt(256 - challenge.difficulty);
    for (let nonce = 0; nonce < this.maxAttempts; nonce++) {
      const attempt = challenge.challenge + ':' + nonce;
      const hash = sha3_256(utf8ToBytes(attempt));
      const hashBigInt = BigInt('0x' + bytesToHex(hash));
      if (hashBigInt < target) return { challenge: challenge.challenge, nonce, hash: bytesToHex(hash), attempts: nonce + 1 };
    }
    return null;
  }

  verify(challenge, solution) {
    if (!challenge || !solution || challenge.challenge !== solution.challenge) return false;
    if (Date.now() > challenge.expiresAt) return false;
    const attempt = solution.challenge + ':' + solution.nonce;
    const hash = sha3_256(utf8ToBytes(attempt));
    const hashHex = bytesToHex(hash);
    if (hashHex !== solution.hash) return false;
    const target = BigInt(2) ** BigInt(256 - challenge.difficulty);
    return BigInt('0x' + hashHex) < target;
  }
}

export class ReputationTracker {
  constructor(options = {}) {
    this.nodes = new Map();
    this.thresholds = { trusted: 0.6, normal: 0.3, suspicious: 0.1, banned: 0.0 };
  }

  registerNode(nodeId, NAVRSolution = null) {
    if (this.nodes.has(nodeId)) return this.nodes.get(nodeId);
    const record = { nodeId, reputation: NAVRSolution ? 0.3 : 0.1, registeredAt: Date.now(), lastSeen: Date.now(), goodBehaviors: 0, badBehaviors: 0 };
    this.nodes.set(nodeId, record);
    return record;
  }

  getTrustLevel(nodeId) {
    const r = this.nodes.get(nodeId);
    if (!r) return 'unknown';
    if (r.reputation >= this.thresholds.trusted) return 'trusted';
    if (r.reputation >= this.thresholds.normal) return 'normal';
    if (r.reputation >= this.thresholds.suspicious) return 'suspicious';
    return 'banned';
  }

  reportGoodBehavior(nodeId, weight = 0.01) {
    const r = this.nodes.get(nodeId);
    if (r) { r.goodBehaviors++; r.lastSeen = Date.now(); r.reputation = Math.min(1.0, r.reputation + weight); }
  }

  reportBadBehavior(nodeId, weight = 0.1) {
    const r = this.nodes.get(nodeId);
    if (r) { r.badBehaviors++; r.reputation = Math.max(0.0, r.reputation - weight); }
  }

  getStats() {
    let trusted = 0, normal = 0, suspicious = 0, banned = 0;
    for (const r of this.nodes.values()) {
      const l = this.getTrustLevel(r.nodeId);
      if (l === 'trusted') trusted++; else if (l === 'normal') normal++; else if (l === 'suspicious') suspicious++; else banned++;
    }
    return { total: this.nodes.size, trusted, normal, suspicious, banned };
  }
}

export class SubnetDiversity {
  constructor(options = {}) {
    this.maxPerSubnet = options.maxPerSubnet || 3;
    this.subnets = new Map();
    this.connections = new Map();
  }

  getSubnet(ip) {
    if (!ip) return 'unknown';
    // Normalize IPv4-mapped IPv6 (::ffff:192.168.1.1 → 192.168.1.1)
    if (ip.includes('::ffff:')) ip = ip.split('::ffff:')[1];
    // IPv4: /24 subnet (first 3 octets)
    if (ip.includes('.')) return ip.split('.').slice(0, 3).join('.');
    // Pure IPv6: /64 prefix (first 4 hextets) — prevents dual-stack Sybil bypass
    if (ip.includes(':')) return ip.split(':').slice(0, 4).join(':');
    return 'unknown';
  }

  allowConnection(ip) {
    const subnet = this.getSubnet(ip);
    const count = this.subnets.get(subnet) || 0;
    if (count >= this.maxPerSubnet) return { allowed: false, reason: 'Too many from subnet ' + subnet };
    return { allowed: true };
  }

  addConnection(ip, nodeId) {
    const subnet = this.getSubnet(ip);
    this.subnets.set(subnet, (this.subnets.get(subnet) || 0) + 1);
    this.connections.set(ip, nodeId);
  }

  removeConnection(ip) {
    const subnet = this.getSubnet(ip);
    const count = this.subnets.get(subnet) || 0;
    if (count > 0) this.subnets.set(subnet, count - 1);
    this.connections.delete(ip);
  }
}

export class SybilDefense {
  constructor(options = {}) {
    this.NAVR = new NAVR(options.NAVR || {});
    this.reputation = new ReputationTracker(options.reputation || {});
    this.diversity = new SubnetDiversity(options.diversity || {});
  }

  /**
   * Evaluate a connection request.
   * Returns `allowed` boolean (backward compat) plus `verdict` trit:
   *   POSITIVE: accept, NEUTRAL: challenge required, NEGATIVE: reject
   */
  evaluateConnection(ip, nodeId, NAVRSolution = null) {
    const divCheck = this.diversity.allowConnection(ip);
    if (!divCheck.allowed) return { allowed: false, verdict: NEGATIVE, reason: divCheck.reason };
    let record = this.reputation.nodes.get(nodeId);
    if (!record) record = this.reputation.registerNode(nodeId, NAVRSolution);
    const trustLevel = this.reputation.getTrustLevel(nodeId);
    if (trustLevel === 'banned') return { allowed: false, verdict: NEGATIVE, reason: 'Node is banned' };
    if (trustLevel === 'unknown' && !NAVRSolution) return { allowed: false, verdict: NEUTRAL, reason: 'NAVR required', challenge: this.NAVR.createChallenge(nodeId) };
    this.diversity.addConnection(ip, nodeId);
    return { allowed: true, verdict: POSITIVE, trustLevel, reputation: record.reputation };
  }

  reportMessage(nodeId, valid) {
    if (valid) this.reputation.reportGoodBehavior(nodeId, 0.005);
    else this.reputation.reportBadBehavior(nodeId, 0.05);
  }

  handleDisconnect(ip) { this.diversity.removeConnection(ip); }

  getStats() { return { reputation: this.reputation.getStats() }; }
}

export default SybilDefense;

