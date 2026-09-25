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
 * Echo Challenge — peer-measured compute conformance.
 *
 * Every timing proof on the mesh today is SELF-measured: silicon-parity
 * AES histograms, hardware-attestation capability runs — the node holds
 * its own stopwatch. This module closes that gap: the CHALLENGER's clock
 * times the responder's work, minus the measured network median from
 * echo-ranging's LatencyTracker. A responder cannot pad below physics,
 * and an outsourced compute hop (forwarding to a faster machine) shows
 * up as MORE time, not less — the attack mostly self-defeats.
 *
 * Wire protocol (direct sendTo — NEVER rumor; rumor flood adds
 * multi-hop jitter that swamps millisecond compute signals):
 *
 *   challenger ── echo:challenge {v,id,nonce,work,epoch,from,pubKey,sig}
 *   target     ── echo:result    {v,id,nonce,result,procNs,work,…,sig}
 *              or echo:refusal   {v,id,reason,…,sig}   (honest refusal)
 *
 * measured computeNs ≈ rttNs − netMedianNs(peer)
 *
 * Work types: 'sha3chain' is the pure-JS sequential workload —
 * unparallelizable, nonce-seeded, identity-bound, recomputable by the
 * challenger (symmetric bounded cost). 'mkc-sha3batch' dispatches a
 * nonce-derived message batch through the integrated pq-bridge MKC —
 * bit-accurate across CPU/GPU/NPU, so the challenger verifies the
 * folded digests in plain JS and the measured time reflects silicon,
 * not the interpreter. The result honestly carries the bridge's own
 * `device` report. A reachable bridge is expected; refusing with
 * 'unavailable' marks a degraded node — legible, not fatal.
 *
 * Results are end-to-end signed (ML-DSA via identity.sign) and bind
 * nodeId→pubKey — the response IS a witnessed transcript artifact.
 *
 * @module mesh/echo-challenge
 * @license YakMesh-NE-1.0 (YAKMESH NETWORK ENGINE LICENSE AGREEMENT v1.0)
 * @copyright 2026 YAKMESH™ Contributors
 */

import { EventEmitter } from 'events';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import { seedStore } from '../security/prahari.js';
import { verifySignature, generateNodeId } from '../identity/node-key.js';
import { createLogger } from '../utils/logger.js';
import { EchoRanging, LatencyTracker } from './echo-ranging.js';

const log = createLogger('mesh:echo-challenge');

const ECHALLENGE_VERSION = 1;

const CONFIG = {
  challengeTimeoutMs: 15000,   // pending challenge lifetime
  defaultRounds: 4096,         // default sha3chain length (~ms-scale)
  maxInboundRounds: 16384,     // refuse larger — inbound work is unrequested
  maxInboundMkcMsgs: 512,      // mkc-sha3batch message cap
  defaultMkcCount: 64,         // default mkc-sha3batch size
  perPeerCooldownMs: 5000,     // min gap between inbound challenges per peer
  maxConcurrentInbound: 4,     // global cap on simultaneous inbound work
  maxPending: 64,              // outbound pending bound
  maxSamplesPerPeer: 32,       // conformance history window
  probeFanout: 8,              // max peers probed per interval
};

const WORK_DOMAIN = 'echo:work:v1';
const MKC_WORK_DOMAIN = 'echo:mkc:v1';

/**
 * Sequential SHA3-256 chain. x0 = sha3(domain ‖ nonce ‖ responderId);
 * x_{i+1} = sha3(x_i). Inherently serial — a farm cannot parallelize it,
 * and the seed binds the chain to the responder's identity so a correct
 * result is non-transferable across nodeIds.
 */
export function workSha3Chain(nonceHex, responderId, rounds) {
  let x = sha3_256(concatBytes(
    utf8ToBytes(WORK_DOMAIN),
    hexToBytes(nonceHex),
    utf8ToBytes(responderId),
  ));
  for (let i = 0; i < rounds; i++) x = sha3_256(x);
  return bytesToHex(x);
}

/**
 * Deterministic message batch for 'mkc-sha3batch' work. Cheap
 * concatenation — the work itself is the batch dispatch, and the
 * identity binding makes a correct fold non-transferable.
 */
export function mkcBatchMessages(nonceHex, responderId, count) {
  const pre = concatBytes(
    utf8ToBytes(MKC_WORK_DOMAIN), hexToBytes(nonceHex),
    utf8ToBytes(responderId));
  const msgs = [];
  for (let i = 0; i < count; i++) {
    const m = new Uint8Array(pre.length + 4);
    m.set(pre);
    new DataView(m.buffer).setUint32(pre.length, i, true);
    msgs.push(m);
  }
  return msgs;
}

/** Fold a digest batch into the single committed result. */
export function mkcFoldDigests(digests) {
  return bytesToHex(sha3_256(concatBytes(...digests)));
}

/**
 * Challenger-side expected result — MKC digests are bit-accurate, so
 * the fold recomputes in plain JS with no bridge required.
 */
export function expectedResult(work, nonceHex, responderId) {
  if (work?.type === 'sha3chain')
    return workSha3Chain(nonceHex, responderId, work.rounds);
  if (work?.type === 'mkc-sha3batch')
    return mkcFoldDigests(
      mkcBatchMessages(nonceHex, responderId, work.count)
        .map(m => sha3_256(m)));
  return null;
}

/** Work echo check — the responder must echo the issued spec verbatim. */
function workMatches(issued, echoed) {
  if (!echoed || echoed.type !== issued.type) return false;
  return Object.keys(issued)
    .every(k => String(echoed[k]) === String(issued[k]));
}

/** Canonical signature payload — same convention as attestation batches. */
function signedPayload(obj) {
  return JSON.stringify({ ...obj, sig: undefined });
}

/** Verify inner sig + nodeId↔pubKey binding. Returns boolean. */
function verifyBound(msg) {
  if (typeof msg.pubKey !== 'string' || typeof msg.sig !== 'string' ||
      typeof msg.from !== 'string') return false;
  try {
    if (generateNodeId(hexToBytes(msg.pubKey)) !== msg.from) return false;
    return verifySignature(signedPayload(msg), msg.sig, msg.pubKey);
  } catch {
    return false;
  }
}

/**
 * Challenger + responder for peer-measured compute conformance.
 */
export class EchoChallenge extends EventEmitter {
  /**
   * @param {object} opts
   * @param {string} opts.nodeId      - our yakmesh nodeId
   * @param {string} opts.publicKey   - our ML-DSA pubkey hex
   * @param {function} opts.sign      - (json:string) => sigHex
   * @param {function} opts.send      - (peerId, msg) => void  (mesh.sendTo)
   * @param {function} [opts.netMedianNs] - (peerId, wire) => bigint|null
   * @param {function} [opts.wireOf]  - (peerId) => 'tun'|'lan'|null —
   *   the wire class our primary socket to the peer rides. YAKTUN and
   *   LAN-lifeline have different RTT physics; the baseline must match
   *   the wire the challenge actually used.
   * @param {function} [opts.envelopeFor] - (peerId, work) => {minNs,maxNs}|null
   * @param {function} [opts.executor] - (work, nonce, responderId) =>
   *   Promise<{result:string, procNs:bigint}> — override for tests /
   *   accelerated backends. Default: synchronous sha3chain.
   * @param {object} [opts.config] - CONFIG overrides (tests)
   */
  constructor(opts) {
    super();
    this.cfg = { ...CONFIG, ...(opts.config || {}) };
    this.nodeId = opts.nodeId;
    this.publicKey = opts.publicKey;
    this.sign = opts.sign;
    this.send = opts.send;
    this.netMedianNs = opts.netMedianNs || (() => null);
    this.wireOf = opts.wireOf || (() => null);
    /** MKC client surface (utils/mkc) — injectable for tests. */
    this.mkc = opts.mkc || null;
    /** Self-declared capability bands per work type, echoed in every
     *  echo:result. Accepts a map {sha3chain:'copper',…} or a legacy
     *  bare string (read as the sha3chain band). */
    const bh = opts.bandHint;
    this.bandHint = bh && typeof bh === 'object' ? { ...bh }
                  : typeof bh === 'string' ? { sha3chain: bh }
                  : null;
    /** peerId → declared band, captured from verified results. */
    this.peerBands = new Map();
    this.envelopeFor = opts.envelopeFor || (() => null);
    this.executor = opts.executor || null;

    /** @type {Map<string, {targetId:string, sentAt:bigint, work:object, nonce:string, timer:Timeout}>} */
    this.pending = new Map();
    /** @type {Map<string, Array<object>>} peerId → conformance samples */
    this.samples = new Map();
    /** inbound rate state */
    this.inboundLast = new Map();  // challengerId → last ms
    this.inboundInflight = 0;

    this.stats = {
      issued: 0, verified: 0, failed: 0, timeouts: 0,
      refusals: 0, anomalies: 0, served: 0, refused: 0,
    };
  }

  // ─── challenger side ────────────────────────────────────────────────

  /**
   * Issue a compute challenge to a peer. Returns challenge id or null
   * if the pending map is saturated.
   */
  challenge(peerId, work = { type: 'sha3chain', rounds: this.cfg.defaultRounds }) {
    if (this.pending.size >= this.cfg.maxPending) return null;
    const id = bytesToHex(seedStore.squeeze(16, 'ECHO-CHALLENGE-ID'));
    const nonce = bytesToHex(seedStore.squeeze(32, 'ECHO-CHALLENGE-NONCE'));

    const msg = {
      type: 'echo:challenge',
      v: ECHALLENGE_VERSION,
      id, nonce,
      epoch: Math.floor(Date.now() / 30000),
      work,
      deadlineMs: this.cfg.challengeTimeoutMs,
      from: this.nodeId,
      pubKey: this.publicKey,
    };
    msg.sig = this.sign(signedPayload(msg));

    const timer = setTimeout(() => {
      const p = this.pending.get(id);
      if (!p) return;
      this.pending.delete(id);
      this.stats.timeouts++;
      this.emit('timeout', { peerId: p.targetId, id, work: p.work });
    }, this.cfg.challengeTimeoutMs);
    if (timer.unref) timer.unref();

    this.pending.set(id, {
      targetId: peerId, sentAt: process.hrtime.bigint(),
      work, nonce, epoch: msg.epoch,
      wire: this.wireOf(peerId), timer,
    });
    this.send(peerId, msg);
    this.stats.issued++;
    this.emit('issued', { peerId, id, work });
    return id;
  }

  /**
   * Handle echo:result. Verification order: pending → identity binding →
   * work echo → result correctness → timing.
   */
  handleResult(msg) {
    if (!msg || msg.v !== ECHALLENGE_VERSION) return;
    const pending = this.pending.get(msg.id);
    if (!pending) return; // unknown/expired — normal under network timing
    if (msg.from !== pending.targetId || msg.nonce !== pending.nonce) {
      this.stats.failed++;
      return;
    }
    if (!verifyBound(msg)) {
      this.stats.failed++;
      this.emit('failed', { peerId: msg.from, id: msg.id, reason: 'bad-signature' });
      return;
    }
    // Work echo must match what we issued verbatim — a responder
    // claiming a smaller work spec is a soft forgery.
    const w = pending.work;
    if (!workMatches(w, msg.work)) {
      this.stats.failed++;
      this.emit('failed', { peerId: msg.from, id: msg.id, reason: 'work-mismatch' });
      return;
    }

    // Correctness: recompute (symmetric bounded cost — we only issue
    // what we can afford to verify). MKC digests are bit-accurate, so
    // the fold recomputes in plain JS with no bridge required.
    let expected;
    try {
      expected = expectedResult(w, pending.nonce, pending.targetId);
    } catch {
      return;
    }
    if (expected == null) return; // unknown work type we issued?
    if (msg.result !== expected) {
      this.stats.failed++;
      this.emit('failed', { peerId: msg.from, id: msg.id, reason: 'bad-result' });
      return;
    }

    // Verified result — the peer's declared capability bands are now a
    // signed, witnessed statement we can hold it to next challenge.
    const bh = msg.bandHint;
    if (bh && typeof bh === 'object' &&
        Object.keys(bh).length <= 8 &&
        Object.values(bh).every(v => typeof v === 'string' && v.length <= 32)) {
      this.peerBands.set(pending.targetId, { ...bh });
    } else if (typeof bh === 'string' && bh.length <= 32) {
      this.peerBands.set(pending.targetId, { sha3chain: bh });
    }

    clearTimeout(pending.timer);
    this.pending.delete(msg.id);

    const rttNs = process.hrtime.bigint() - pending.sentAt;
    const netNs = this.netMedianNs(pending.targetId, pending.wire);
    const procNs = msg.procNs != null ? BigInt(msg.procNs) : null;
    const adjusted = netNs != null;
    const computeNs = adjusted && rttNs > netNs ? rttNs - netNs : rttNs;

    const envelope = this.envelopeFor(pending.targetId, w);
    let band = 'unclassified';
    if (envelope) {
      band = computeNs < envelope.minNs ? 'fast'
           : computeNs > envelope.maxNs ? 'slow' : 'ok';
      if (band !== 'ok') {
        this.stats.anomalies++;
        this.emit('anomaly', {
          peerId: pending.targetId, id: msg.id, band,
          computeNs: Number(computeNs), envelope,
        });
      }
    }

    const sample = {
      at: Date.now(), epoch: pending.epoch,
      work: { ...w }, rttNs: Number(rttNs), wire: pending.wire,
      netNs: netNs != null ? Number(netNs) : null,
      computeNs: Number(computeNs), adjusted,
      procNs: procNs != null ? Number(procNs) : null,
      skewNs: procNs != null ? Number(procNs - computeNs) : null,
      device: typeof msg.device === 'string' ? msg.device : null,
      band,
    };
    let arr = this.samples.get(pending.targetId);
    if (!arr) { arr = []; this.samples.set(pending.targetId, arr); }
    arr.push(sample);
    if (arr.length > this.cfg.maxSamplesPerPeer) arr.shift();

    this.stats.verified++;
    this.emit('measured', { peerId: pending.targetId, id: msg.id, ...sample });
  }

  /**
   * Handle echo:refusal — legible non-service, distinct from failure.
   */
  handleRefusal(msg) {
    if (!msg || msg.v !== ECHALLENGE_VERSION) return;
    const pending = this.pending.get(msg.id);
    if (!pending || msg.from !== pending.targetId || !verifyBound(msg)) return;
    clearTimeout(pending.timer);
    this.pending.delete(msg.id);
    this.stats.refusals++;
    this.emit('refused', { peerId: msg.from, id: msg.id, reason: msg.reason });
  }

  // ─── responder side ─────────────────────────────────────────────────

  /**
   * Handle echo:challenge. Validates shape, signature+binding, and
   * inbound rate limits before touching any work. Never throws.
   */
  async handleChallenge(msg) {
    if (!msg || msg.v !== ECHALLENGE_VERSION) return;
    if (msg.from === this.nodeId) return;
    if (!verifyBound(msg)) return;
    if (typeof msg.id !== 'string' || !/^[0-9a-f]{16,64}$/.test(msg.id) ||
        typeof msg.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(msg.nonce)) {
      return;
    }

    const refuse = (reason) => {
      const r = {
        type: 'echo:refusal', v: ECHALLENGE_VERSION,
        id: msg.id, reason, from: this.nodeId, pubKey: this.publicKey,
      };
      r.sig = this.sign(signedPayload(r));
      this.send(msg.from, r);
      this.stats.refused++;
      this.emit('refusing', { peerId: msg.from, id: msg.id, reason });
    };

    // Rate limits — inbound work is unrequested CPU. Per-peer cooldown,
    // global concurrency cap, rounds cap.
    const last = this.inboundLast.get(msg.from) || 0;
    if (Date.now() - last < this.cfg.perPeerCooldownMs) return refuse('rate');
    if (this.inboundInflight >= this.cfg.maxConcurrentInbound) return refuse('busy');

    const work = msg.work || {};
    if (work.type !== 'sha3chain' && work.type !== 'mkc-sha3batch') {
      return refuse('unsupported');
    }
    if (work.type === 'sha3chain') {
      const rounds = Number(work.rounds);
      if (!Number.isInteger(rounds) || rounds < 1 || rounds > this.cfg.maxInboundRounds) {
        return refuse('oversize');
      }
    } else {
      const count = Number(work.count);
      if (!Number.isInteger(count) || count < 1 || count > this.cfg.maxInboundMkcMsgs) {
        return refuse('oversize');
      }
      if (!this.executor) {
        const mkc = this.mkc || await import('../utils/mkc.js').catch(() => null);
        if (!mkc || !(await mkc.isAvailable().catch(() => false))) {
          // Degraded: the bridge is integrated but currently unreachable.
          return refuse('unavailable');
        }
        this._mkc = mkc;
      }
    }

    this.inboundLast.set(msg.from, Date.now());
    this.inboundInflight++;
    const t0 = process.hrtime.bigint();
    try {
      let result, procNs, device;
      if (this.executor) {
        ({ result, procNs, device } = await this.executor(work, msg.nonce, this.nodeId));
      } else if (work.type === 'mkc-sha3batch') {
        const msgs = mkcBatchMessages(msg.nonce, this.nodeId, work.count);
        const r = await this._mkc.sha3_256Batch(msgs);
        result = mkcFoldDigests(r.digests);
        device = r.device; // the bridge's own honest executor report
        procNs = process.hrtime.bigint() - t0;
      } else {
        result = workSha3Chain(msg.nonce, this.nodeId, work.rounds);
        procNs = process.hrtime.bigint() - t0;
      }
      const resp = {
        type: 'echo:result', v: ECHALLENGE_VERSION,
        id: msg.id, nonce: msg.nonce,
        epoch: msg.epoch,
        result: String(result),
        procNs: procNs != null ? String(procNs) : null,
        device: device || null,
        bandHint: this.bandHint,
        work,
        from: this.nodeId, pubKey: this.publicKey,
      };
      resp.sig = this.sign(signedPayload(resp));
      this.send(msg.from, resp);
      this.stats.served++;
    } catch {
      refuse('error');
    } finally {
      this.inboundInflight--;
    }
  }

  /** Conformance samples for a peer (bounded window). */
  peerSamples(peerId) {
    return this.samples.get(peerId) || [];
  }

  getStats() { return { ...this.stats }; }
}

/**
 * Wire the ECHO stack into the mesh: latency probes (cartography +
 * network-RTT baseline) and compute challenges (peer-measured work).
 *
 * Registers four direct-message handlers on `mesh`:
 *   echo:probe      → respond instantly (network baseline sample)
 *   echo:response   → feed LatencyTracker + coordinate update
 *   echo:challenge  → validate, rate-limit, execute, respond
 *   echo:result     → verify + measure + conformance sample
 *   echo:refusal    → legible non-service
 *
 * @param {Object} params
 * @param {Object} params.mesh       - MandalaNetwork instance
 * @param {string} params.nodeId
 * @param {string} params.publicKey
 * @param {function} params.sign     - (json) => sigHex
 * @param {function} [params.envelopeFor] - conformance envelope lookup
 * @param {Object} [params.bands] - {hint:{workType→band}, envelopeFor}
 *   enables declared-band envelopes (challenger) + bandHint echo
 * @param {Object|string} [params.bandHint] - our declared bands
 *   (per-work-type map preferred; bare string = sha3chain band)
 * @param {Object} [params.mkc] - utils/mkc surface (injected for tests)
 * @param {Object} [params.log]
 * @param {Object} [opts] - partial CONFIG overrides (tests)
 * @returns {{echo:EchoRanging, challenger:EchoChallenge, stop:Function,
 *            probePeer:Function, challengePeer:Function}}
 */
export function wireEcho({ mesh, nodeId, publicKey, sign, envelopeFor, bands, bandHint, mkc, controller, log: extLog, opts = {} }) {
  const cfg = { ...CONFIG, ...opts };

  const echo = new EchoRanging({ nodeId });

  // Per-wire latency baselines. The double-wire system gives each peer
  // two paths with different physics — YAKTUN overlay ('tun', primary
  // when up) and direct LAN ('lan', the lifeline). A single per-peer
  // median would silently mix both wires and go stale on failover.
  /** @type {Map<string, LatencyTracker>} key: `${peerId}@${wireClass}` */
  const wireLat = new Map();
  const wireClassOf = (peerId, which = 'primary') => {
    const via = mesh.peers?.get(peerId)?.wsVia || 'lan';
    return which === 'lifeline' ? (via === 'tun' ? 'lan' : 'tun') : via;
  };

  const challenger = new EchoChallenge({
    nodeId, publicKey, sign,
    config: opts,
    bandHint: bandHint || bands?.hint || bands?.band || null,
    mkc,
    send: (peerId, msg) => mesh.sendTo(peerId, msg),
    wireOf: (peerId) => wireClassOf(peerId),
    netMedianNs: (peerId, wire) => {
      const wireStats = wire && wireLat.get(`${peerId}@${wire}`)?.getStats();
      if (wireStats) return wireStats.median;
      const stats = echo.peerLatencies.get(peerId)?.getStats();
      return stats ? stats.median : null;
    },
    // Bands wired? Envelope = the peer's declared band from its last
    // verified result. Cold start (no verified result yet) → null →
    // the sample lands 'unclassified' — honest, not a failure.
    // Controller present → per-peer dynamic tolerance (fuse model,
    // detection-only); absent → static TOLERANCE baseline.
    envelopeFor: envelopeFor || (bands
      ? (peerId, work) => bands.envelopeFor(
          work, challenger.peerBands.get(peerId),
          controller ? controller.toleranceFor(peerId) : undefined)
      : null),
  });

  // Feed witnessed outcomes into the controller — measured samples,
  // refusals, timeouts, failures all shape the peer's scrutiny level.
  if (controller) {
    challenger.on('measured', (s) => controller.observe(s.peerId, s));
    challenger.on('refused', (s) => controller.observe(s.peerId, { refused: s.reason }));
    challenger.on('timeout', (s) => controller.observe(s.peerId, { timeout: true }));
    challenger.on('failed', (s) => controller.observe(s.peerId, { failed: s.reason }));
  }

  const sendProbe = (peerId, which = 'primary') => {
    const probe = echo.createProbe(peerId);
    const pend = echo.pendingProbes.get(probe.probeId);
    if (pend) pend.wire = wireClassOf(peerId, which);
    mesh.sendTo(peerId, { type: 'echo:probe', probe },
      which === 'lifeline' ? { wire: 'lifeline' } : undefined);
  };

  // ─── probes: network-RTT baseline ─────────────────────────────────
  mesh.on('echo:probe', (msg, ws, senderNodeId) => {
    if (senderNodeId === nodeId || !msg?.probe) return;
    const resp = echo.handleProbe(msg.probe, senderNodeId);
    if (resp && !resp.error) {
      // Reply on the wire the probe arrived on — per-wire RTT only
      // works if the whole exchange rides one wire.
      const onLifeline = mesh.peers?.get(senderNodeId)?.lifelineWs === ws;
      mesh.sendTo(senderNodeId, { type: 'echo:response', response: resp },
        onLifeline ? { wire: 'lifeline' } : undefined);
    }
  });

  mesh.on('echo:response', (msg, _ws, senderNodeId) => {
    if (!msg?.response) return;
    // Capture which wire the probe took BEFORE handleResponse deletes it.
    const probeWire = echo.pendingProbes.get(msg.response.probeId)?.wire;
    const r = echo.handleResponse(msg.response);
    // Response must answer a probe we sent to THIS sender — handleResponse
    // already resolves via pendingProbes.targetNodeId; guard the mismatch.
    if (r?.peerId && senderNodeId && r.peerId !== senderNodeId) {
      (extLog || log).warn('echo response from unexpected peer', {
        expected: r.peerId, got: senderNodeId,
      });
    }
    if (r?.peerId && r.rttNs != null && probeWire) {
      const key = `${r.peerId}@${probeWire}`;
      if (!wireLat.has(key)) wireLat.set(key, new LatencyTracker());
      wireLat.get(key).addSample(r.rttNs);
    }
  });

  // ─── challenges: peer-measured compute ────────────────────────────
  mesh.on('echo:challenge', (msg, _ws, senderNodeId) => {
    if (!msg || msg.from !== senderNodeId) return; // hop-auth binding
    challenger.handleChallenge(msg).catch(() => {});
  });

  mesh.on('echo:result', (msg, _ws, senderNodeId) => {
    if (!msg || msg.from !== senderNodeId) return;
    challenger.handleResult(msg);
  });

  mesh.on('echo:refusal', (msg, _ws, senderNodeId) => {
    if (!msg || msg.from !== senderNodeId) return;
    challenger.handleRefusal(msg);
  });

  // ─── probe loop: 30s cadence over direct peers (capped) ───────────
  const probeTimer = setInterval(() => {
    const peers = [...(mesh.peers?.keys() || [])]
      .filter(p => p !== nodeId)
      .slice(0, cfg.probeFanout);
    for (const p of peers) {
      try {
        sendProbe(p, 'primary');
        // Double-wire: also measure the lifeline so its baseline is
        // fresh when a failover flips wsVia mid-epoch.
        const life = mesh.peers?.get(p)?.lifelineWs;
        if (life && life.readyState === 1 /* WebSocket.OPEN */) {
          sendProbe(p, 'lifeline');
        }
      } catch { /* peer churn mid-probe is normal */ }
    }
  }, cfg.probeIntervalMs || 30000);
  if (probeTimer.unref) probeTimer.unref();

  // ─── challenge loop: spot-check cadence over direct peers ──────────
  // Default off (0) — the server opts in; tests and embedders may not.
  let challengeTimer = null;
  if (cfg.challengeIntervalMs > 0) {
    challengeTimer = setInterval(() => {
      const peers = [...(mesh.peers?.keys() || [])].filter(p => p !== nodeId);
      if (peers.length === 0) return;
      // One peer per tick — conformance is a spot audit, not a census.
      // Controller present → suspicion-weighted pick (strict peers get
      // audited ~3×, relaxed ~0.5×); absent → uniform random.
      const target = controller
        ? controller.pickTarget(peers)
        : peers[Math.floor(Math.random() * peers.length)];
      if (target) challenger.challenge(target);
    }, cfg.challengeIntervalMs);
    if (challengeTimer.unref) challengeTimer.unref();
  }

  return {
    echo,
    challenger,
    controller: controller || null,
    wireLat,
    probePeer: (peerId, which = 'primary') => sendProbe(peerId, which),
    challengePeer: (peerId, work) => challenger.challenge(peerId, work),
    stop: () => {
      clearInterval(probeTimer);
      if (challengeTimer) clearInterval(challengeTimer);
    },
  };
}
