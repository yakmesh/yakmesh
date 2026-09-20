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
 * Attestation Gossip — the k-of-m layer that turns local witnessing
 * into network consensus on who contributed.
 *
 * Attestations are SIGNED WITNESS STATEMENTS, not claim re-broadcasts:
 * "I, attester A, witnessed claim {epoch, yakmeshNodeId → yakcoinNodeId,
 * seal}". A claim's k-count is the number of DISTINCT attester nodeIds —
 * counted from received attestations, never read from the claim itself
 * (a claimant inflating their own k is the first attack anyone tries).
 *
 * Cadence: at epoch close (30s boundary) each node attests the claims it
 * witnessed in the just-closed epoch. Attestations for epoch E are
 * accepted through E+1 (grace), frozen at E+2 — matches claim-ledger's
 * bounded-epoch model.
 *
 * Fork evidence rides the same rumor: an attester reporting a forked
 * identity produces quorum-visible slashing evidence.
 *
 * @module mesh/attestation-gossip
 */

import { EventEmitter } from 'events';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { verifySignature, generateNodeId } from '../identity/node-key.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('mesh:attestation-gossip');

const ATTEST_VERSION = 1;
const GRACE_EPOCHS = 2;        // attestations for E accepted while now ≤ E+2
const MAX_EPOCHS = 64;         // matches claim-ledger prune horizon

/**
 * Canonical claim key — every attester derives the same key for the
 * same witnessed claim. (epoch, yakmeshNodeId) is canonical because
 * claim-ledger is first-claim-wins per node per epoch.
 */
export function claimKey(epoch, yakmeshNodeId) {
  return bytesToHex(sha3_256(utf8ToBytes(`${epoch}:${yakmeshNodeId}`)));
}

/** What one attester signed over — the full attested tuple. */
function attestationPreimage(a) {
  return `attest:${a.epoch}:${a.yakmeshNodeId}:${a.claimNodeId}:${a.seal.join(',')}`;
}

export class AttestationGossip extends EventEmitter {
  /**
   * @param {object} opts
   * @param {string} opts.nodeId - our yakmesh nodeId
   * @param {string} opts.publicKey - our ML-DSA-65 pubkey hex
   * @param {function} opts.sign - (data:string) => sigHex
   * @param {ClaimLedger} opts.claimLedger - witness source
   */
  constructor(opts) {
    super();
    this.nodeId = opts.nodeId;
    this.publicKey = opts.publicKey;
    this.sign = opts.sign;
    this.claimLedger = opts.claimLedger;

    /** @type {Map<number, Map<string, Set<string>>>} epoch → claimKey → attesterIds */
    this.attestations = new Map();
    /** @type {Map<string, object>} claimKey → {seal, claimNodeId} first-seen */
    this.claimRefs = new Map();
    /** Fork/binding evidence received from attestations */
    this.reportedEvidence = [];
    this.stats = { sent: 0, received: 0, dupes: 0, badSigs: 0, conflicts: 0 };
  }

  /**
   * Build our attestation batch for a just-closed epoch.
   * One signature covers the batch + any fork evidence we hold.
   */
  buildBatch(epoch) {
    const claims = this.claimLedger.epochClaims(epoch);
    if (claims.length === 0 && this.claimLedger.forks.length === 0) return null;

    // Only attest VERIFIED claims — a witness must not vouch for
    // unsigned or forged beats (v3.5.3 signed-heartbeat fix). Claims
    // that FAILED the AVOTH seal recompute (sealVerified === false, set
    // by claimLedger.verifyEpochSeals at epoch close) are excluded too —
    // seal failure is emitted separately as sealFailure evidence.
    // sealVerified === undefined (bridge unreachable) still attests:
    // verification defers to settlement, never fabricated.
    const items = claims.filter(c =>
      c.verified === 'verified' && c.sealVerified !== false).map(c => ({
      epoch,
      yakmeshNodeId: c.yakmeshNodeId,
      claimNodeId: c.nodeId,
      seal: c.seal,
    }));
    const forks = this.claimLedger.forks.slice(-16).map(f => ({
      nodeId: f.nodeId, sequence: f.sequence, hashA: f.hashA, hashB: f.hashB,
    }));
    const conflicts = this.claimLedger.bindingConflicts.slice(-16);

    const batch = {
      v: ATTEST_VERSION,
      attester: this.nodeId,
      pubKey: this.publicKey,
      epoch,
      items,
      evidence: { forks, conflicts },
      sig: null,
    };
    batch.sig = this.sign(JSON.stringify({ ...batch, sig: undefined }));
    return batch;
  }

  /**
   * Process a received claim:attest batch.
   * @returns {{accepted:number, rejected:number}}
   */
  receive(batch, origin) {
    if (!batch || batch.v !== ATTEST_VERSION || !batch.attester) return { accepted: 0, rejected: 0 };
    if (batch.attester === this.nodeId) return { accepted: 0, rejected: 0 }; // ours

    // Grace window: attestations for E only valid while now ≤ E+2
    const now = Math.floor(Date.now() / 30000);
    if (batch.epoch > now || batch.epoch < now - GRACE_EPOCHS) {
      return { accepted: 0, rejected: batch.items?.length || 0 };
    }

    // Verify batch signature over the signed payload
    const { sig, ...signed } = batch;
    if (!batch.pubKey || !verifySignature(JSON.stringify(signed), sig, batch.pubKey)) {
      this.stats.badSigs++;
      log.warn('attestation batch bad signature', { from: batch.attester });
      return { accepted: 0, rejected: batch.items?.length || 0 };
    }

    // IDENTITY BINDING: batch.attester must derive from batch.pubKey.
    // Otherwise a sybil can mint arbitrary attester nodeIds, each signing
    // a self-consistent batch with its own key, inflating k-of-m counts
    // with identities that don't exist. Same binding as HELLO handshake.
    try {
      if (generateNodeId(hexToBytes(batch.pubKey)) !== batch.attester) {
        this.stats.badSigs++;
        log.warn('attestation batch attester not bound to pubkey', { from: batch.attester });
        return { accepted: 0, rejected: batch.items?.length || 0 };
      }
    } catch {
      return { accepted: 0, rejected: batch.items?.length || 0 };
    }

    let accepted = 0;
    let epochMap = this.attestations.get(batch.epoch);
    if (!epochMap) {
      epochMap = new Map();
      this.attestations.set(batch.epoch, epochMap);
      this._prune();
    }

    for (const item of batch.items || []) {
      const key = claimKey(item.epoch, item.yakmeshNodeId);

      // Seal consistency: two attesters reporting different seals for the
      // same claim = conflict evidence (like binding conflicts)
      const ref = this.claimRefs.get(key);
      const sealStr = item.seal.join(',');
      if (ref && ref.seal !== sealStr) {
        this.stats.conflicts++;
        this.emit('sealConflict', {
          claimKey: key,
          attester: batch.attester,
          sealA: ref.seal, sealB: sealStr,
        });
        continue; // conflicting attestations don't count
      }
      if (!ref) this.claimRefs.set(key, { seal: sealStr, claimNodeId: item.claimNodeId });

      let attesters = epochMap.get(key);
      if (!attesters) {
        attesters = new Set();
        epochMap.set(key, attesters);
      }
      if (attesters.has(batch.attester)) {
        this.stats.dupes++;
        continue; // same attester, same claim — count once
      }
      attesters.add(batch.attester);
      accepted++;
      this.stats.received++;
    }

    // Fork/binding evidence rides along — quorum-visible slashing material
    for (const f of batch.evidence?.forks || []) {
      this.reportedEvidence.push({ kind: 'fork', reporter: batch.attester, ...f });
    }
    for (const c of batch.evidence?.conflicts || []) {
      this.reportedEvidence.push({ kind: 'bindingConflict', reporter: batch.attester, ...c });
    }

    if (accepted > 0) this.emit('attestations', { epoch: batch.epoch, from: batch.attester, accepted });
    return { accepted, rejected: (batch.items?.length || 0) - accepted };
  }

  /**
   * The attested set for settlement — claims with their distinct-attester
   * counts. This is what becomes EpochClaim.attestations.
   */
  attestedSet(epoch) {
    const epochMap = this.attestations.get(epoch);
    if (!epochMap) return [];
    const set = [];
    for (const [key, attesters] of epochMap) {
      const ref = this.claimRefs.get(key);
      const claim = this.claimLedger.epochClaims(epoch)
        .find(c => claimKey(c.epoch, c.yakmeshNodeId) === key);
      set.push({
        claimKey: key,
        yakmeshNodeId: claim?.yakmeshNodeId,
        claimNodeId: ref?.claimNodeId,
        seal: ref?.seal?.split(',').map(Number),
        shares: claim?.shareCount || 0,
        attestations: attesters.size,
      });
    }
    return set;
  }

  _prune() {
    while (this.attestations.size > MAX_EPOCHS) {
      const oldest = Math.min(...this.attestations.keys());
      this.attestations.delete(oldest);
    }
  }
}
