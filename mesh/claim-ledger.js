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
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * Claim Ledger — the witness side of yakcoin contribution transport.
 *
 * Observes received pulse:heartbeat rumors, extracts meshState.contribution,
 * and accumulates the per-epoch witnessed claim set that settlement
 * consumes. Also detects chain forks and identity-binding conflicts:
 *
 * - CHAIN FORK: same (nodeId, sequence), different hash → the node is
 *   emitting divergent histories = cloned identity or rewritten chain.
 *   Cryptographic evidence, not suspicion.
 * - BINDING CONFLICT: same yakmesh nodeId claiming a different yakcoin
 *   nodeId → identity layer mismatch (machine-seed cloned onto another
 *   box, or keystore rebound — either way, witnessed).
 *
 * This is a LOCAL witness record. True k-of-m quorum emerges when nodes
 * gossip their ledger attestations — that aggregation is the settlement
 * layer's job, not this module's.
 *
 * @module mesh/claim-ledger
 */

import { EventEmitter } from 'events';
import { createLogger } from '../utils/logger.js';

const log = createLogger('mesh:claim-ledger');

/**
 * Structural check on a contribution claim — shape only. The wormhole
 * seal's cryptographic validity is verified at settlement (AVOTH
 * recompute); here we only confirm it is well-formed.
 */
function validContributionShape(c) {
  return c
    && c.version === 1
    && Number.isInteger(c.epoch) && c.epoch > 0
    && typeof c.nodeId === 'string' && /^[0-9a-f]{64}$/.test(c.nodeId)
    && Array.isArray(c.seal) && c.seal.length === 4
    && c.seal.every(q => Number.isInteger(q) && q >= 0 && q <= 3)
    && Number.isInteger(c.spongeRounds) && c.spongeRounds >= 0
    && Number.isInteger(c.shareCount) && c.shareCount >= 0
    && typeof c.jobRoot === 'string' && /^[0-9a-f]{64}$/.test(c.jobRoot)
    && Number.isInteger(c.entropyFlags);
}

export class ClaimLedger extends EventEmitter {
  constructor(options = {}) {
    super();
    this.nodeId = options.nodeId;            // our yakmesh nodeId (skip self)
    this.maxEpochs = options.maxEpochs || 64;

    /** @type {Map<string, Map<string, object>>} epoch → nodeId → claim */
    this.epochs = new Map();

    /** @type {Map<string, Map<number, string>>} nodeId → seq → hash */
    this.seenSeq = new Map();

    /** @type {Map<string, string>} yakmesh nodeId → yakcoin nodeId */
    this.bindings = new Map();

    this.forks = [];        // recorded fork evidence
    this.bindingConflicts = [];
  }

  /**
   * Observe a received heartbeat. Call for every pulse:heartbeat rumor.
   * @param {object} hb - serialized heartbeat (post-deserialize)
   */
  observe(hb) {
    if (!hb || !hb.nodeId || hb.nodeId === this.nodeId) return;

    this._checkFork(hb);

    const c = hb.meshState?.contribution;
    if (!c) return; // unattested heartbeat — nothing to record

    if (!validContributionShape(c)) {
      log.warn('malformed contribution claim', { from: hb.nodeId });
      this.emit('malformed', { nodeId: hb.nodeId, claim: c });
      return;
    }

    this._checkBinding(hb.nodeId, c.nodeId);

    // Record into the epoch bucket (first claim per node per epoch wins —
    // a node can't upgrade its claim mid-epoch; conflicts are evidence)
    let bucket = this.epochs.get(c.epoch);
    if (!bucket) {
      bucket = new Map();
      this.epochs.set(c.epoch, bucket);
      this._prune();
    }
    if (!bucket.has(hb.nodeId)) {
      bucket.set(hb.nodeId, {
        ...c,
        yakmeshNodeId: hb.nodeId,
        firstSeenSeq: hb.sequence,
        witnessedAt: hb.timestamp,
      });
      this.emit('claim', bucket.get(hb.nodeId));
    }
  }

  /**
   * Fork detection: a second heartbeat for (nodeId, sequence) with a
   * different hash is proof of divergent chain emission.
   */
  _checkFork(hb) {
    let seqs = this.seenSeq.get(hb.nodeId);
    if (!seqs) {
      seqs = new Map();
      this.seenSeq.set(hb.nodeId, seqs);
    }
    const seenHash = seqs.get(hb.sequence);
    if (seenHash && seenHash !== hb.hash) {
      const evidence = {
        nodeId: hb.nodeId,
        sequence: hb.sequence,
        hashA: seenHash,
        hashB: hb.hash,
        at: Date.now(),
      };
      this.forks.push(evidence);
      log.warn('⛓️ CHAIN FORK — cloned identity or rewritten history', evidence);
      this.emit('fork', evidence);
      return;
    }
    if (!seenHash) seqs.set(hb.sequence, hb.hash);
    // bound memory per node
    if (seqs.size > 600) {
      const oldest = Math.min(...seqs.keys());
      seqs.delete(oldest);
    }
  }

  /**
   * yakmesh nodeId ↔ yakcoin nodeId binding — first claim wins.
   */
  _checkBinding(yakmeshNodeId, yakcoinNodeId) {
    const bound = this.bindings.get(yakmeshNodeId);
    if (bound && bound !== yakcoinNodeId) {
      const conflict = { yakmeshNodeId, boundA: bound, boundB: yakcoinNodeId, at: Date.now() };
      this.bindingConflicts.push(conflict);
      log.warn('BINDING CONFLICT — node claims different yakcoin identity', conflict);
      this.emit('bindingConflict', conflict);
      return;
    }
    if (!bound) this.bindings.set(yakmeshNodeId, yakcoinNodeId);
  }

  /** All witnessed claims for an epoch → what settlement consumes. */
  epochClaims(epoch) {
    return [...(this.epochs.get(epoch)?.values() || [])];
  }

  /** Fork evidence for a node — empty = clean record. */
  forksFor(nodeId) {
    return this.forks.filter(f => f.nodeId === nodeId);
  }

  _prune() {
    while (this.epochs.size > this.maxEpochs) {
      const oldest = Math.min(...this.epochs.keys());
      this.epochs.delete(oldest);
    }
  }
}
