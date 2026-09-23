/**
 * TribhujMirror — keeps the 162T routing table resident on the NPU
 *
 * Mirrors a TernaryRoutingTable into MLIR_AIE_TRIBH (0x9c0) via the
 * YakOS MKC bridge (localhost:9995). The table lives on-tile in the
 * NPU trust domain — per-tile 256 slots of packed trits — and the
 * tier/trit distance math for peer selection runs on AIE2 hardware.
 *
 * Design:
 *   - attach() monkey-patches addPeer/removePeer so the mirror can
 *     never desync through the public API (SET replicates to all 16
 *     tiles — identical tables, 16× query throughput).
 *   - All NPU ops go through one serial queue; a failed op marks the
 *     device down for 30s and flags the table stale. On recovery the
 *     whole table is re-synced (≤256 SETs).
 *   - Shared-ctx landmine: a FOREIGN kernel launch on the fused ctx
 *     reinitializes tile memory, silently clobbering the resident
 *     table while the bridge stays up. Every response carries an
 *     'epoch' (foreign-dispatch counter); a read whose epoch differs
 *     from our last write's epoch means the table is gone — we mark
 *     stale and resync rather than serve clobbered data.
 *   - selectDiverse() queries distances on-tile when the bridge is up
 *     and the mirror is clean; returns null otherwise so callers fall
 *     back to the identical JS path in TernaryRoutingTable.
 *
 * This is honest acceleration: the JS path computes the same answers
 * in microseconds — the NPU's value is residency (table never leaves
 * the tile), always-on availability, and zero host cycles. Stats
 * report which device actually served each call.
 *
 * @module oracle/tribhuj-npu
 */

import { createLogger } from '../utils/logger.js';
import { TIER_COUNT, TritAddress } from './ternary-routing.js';
import {
  isAvailable as bridgeAvailable, tribhujSet, tribhujClear,
  tribhujPop, tribhujQuery, tribhujTopk,
} from '../utils/mkc.js';

const log = createLogger('oracle:tribhuj-npu');

const PROBE_MS = 30000;
const MAX_SLOTS = 256;          // per-tile table capacity
const CANARY_SLOT = 255;        // reserved — peers use 0..254
const INVALID = 0xFFFF;

/** Deterministic canary address — written to slot 255 at sync; every
 *  QUERY verifies the tile's returned (tritDist, tierDist) for it
 *  against host-computed truth. Catches on-tile table corruption that
 *  the epoch counter cannot see (foreign launches from OTHER hw
 *  contexts on the shared partition — rust-embed, declare, audio). */
function _canaryAddress() {
  const trits = new Int8Array(162);
  for (let i = 0; i < 162; i++) trits[i] = [1, -1, 0][i % 3];
  return new TritAddress(trits);
}
const CANARY = _canaryAddress();

export class TribhujMirror {
  /**
   * @param {import('./ternary-routing.js').TernaryRoutingTable} table
   */
  constructor(table) {
    this.table = table;
    this._slots = new Map();     // peerId -> slot
    this._free = [];             // recycled slots
    this._next = 0;
    this._q = Promise.resolve(); // serial op queue
    this._up = { ok: false, checked: 0 };
    this._downUntil = 0;
    this._stale = true;          // starts dirty — first sync cleans it
    this._epoch = null;          // resident-state generation of our last write
    this._pop = null;            // expected on-tile table size (incl. canary)
    this._attached = false;
    this._stats = { sets: 0, clears: 0, queries: 0, npuSelects: 0,
                    syncs: 0, errors: 0 };
  }

  // ── attach / mirror ──────────────────────────────────────────────

  /** Wrap addPeer/removePeer so every table mutation mirrors to NPU. */
  attach() {
    if (this._attached) return;
    const origAdd = this.table.addPeer.bind(this.table);
    const origRem = this.table.removePeer.bind(this.table);
    const self = this;

    this.table.addPeer = function (peerId, peerAddress, rtt = 0) {
      const ok = origAdd(peerId, peerAddress, rtt);
      if (ok) self._enqueue(() => self._opSet(peerId, peerAddress));
      return ok;
    };
    this.table.removePeer = function (peerId) {
      const ok = origRem(peerId);
      if (ok) self._enqueue(() => self._opClear(peerId));
      return ok;
    };

    this._attached = true;
    this._probe();               // kicks the first sync when up
    this._probeTimer = setInterval(() => this._probe(), PROBE_MS);
    this._probeTimer.unref?.();
    log.debug('tribhuj mirror attached');
  }

  detach() {
    if (this._probeTimer) clearInterval(this._probeTimer);
    this._attached = false;
  }

  // ── health ───────────────────────────────────────────────────────

  async _probe() {
    if (Date.now() < this._downUntil) { this._up.ok = false; return false; }
    const ok = await bridgeAvailable();
    const was = this._up.ok;
    this._up = { ok, checked: Date.now() };
    try {
      if (ok && (!was || this._stale)) await this.sync();
    } catch {
      this._up.ok = false;
      return false;
    }
    return ok;
  }

  /** True when the bridge is reachable AND the mirror is in sync. */
  get ready() {
    return this._up.ok && !this._stale && Date.now() >= this._downUntil;
  }

  // ── serial op queue ──────────────────────────────────────────────

  _enqueue(fn) {
    this._q = this._q.then(async () => {
      if (!this._up.ok || Date.now() < this._downUntil) {
        this._stale = true;   // dropped op — table must resync
        return;
      }
      try { await fn(); } catch (err) {
        this._stats.errors++;
        this._stale = true;
        this._downUntil = Date.now() + PROBE_MS;
        this._up.ok = false;
        log.debug(`tribhuj op failed (down 30s): ${err.message}`);
      }
    }).catch(() => {});
  }

  _slotFor(peerId) {
    let s = this._slots.get(peerId);
    if (s === undefined) {
      s = this._free.length ? this._free.pop() : this._next++;
      if (s >= CANARY_SLOT) { this._next--; return -1; }
      this._slots.set(peerId, s);
    }
    return s;
  }

  async _opSet(peerId, address) {
    const slot = this._slotFor(peerId);
    if (slot < 0) return;        // table full on-tile — JS still works
    const resp = await tribhujSet(slot, [...address.toTrits()]);
    if (resp.epoch !== undefined) this._epoch = resp.epoch;
    if (resp.pop !== undefined) this._pop = resp.pop[0];
    this._stats.sets++;
  }

  async _opClear(peerId) {
    const slot = this._slots.get(peerId);
    if (slot === undefined) return;
    const resp = await tribhujClear(slot);
    if (resp.epoch !== undefined) this._epoch = resp.epoch;
    if (resp.pop !== undefined) this._pop = resp.pop[0];
    this._slots.delete(peerId);
    this._free.push(slot);
    this._stats.clears++;
  }

  /** Replay the entire JS table into the NPU (recovery / cold start). */
  async sync() {
    const t0 = Date.now();
    try {
      // Re-SET or CLEAR every slot the mirror already knows about.
      for (const [peerId, slot] of [...this._slots]) {
        const entry = this._entryFor(peerId);
        if (entry) {
          const resp = await tribhujSet(slot, [...entry.address.toTrits()]);
          if (resp.epoch !== undefined) this._epoch = resp.epoch;
          this._stats.sets++;
        } else {
          const resp = await tribhujClear(slot);
          if (resp.epoch !== undefined) this._epoch = resp.epoch;
          this._slots.delete(peerId);
          this._free.push(slot);
          this._stats.clears++;
        }
      }
      // Peers the mirror never saw (pre-attach adds) — scan the table.
      for (const bucket of this.table._buckets) {
        for (const [peerId, entry] of bucket) {
          if (!this._slots.has(peerId)) {
            const slot = this._slotFor(peerId);
            if (slot >= 0) {
              const resp = await tribhujSet(slot, [...entry.address.toTrits()]);
              if (resp.epoch !== undefined) this._epoch = resp.epoch;
              this._stats.sets++;
            }
          }
        }
      }
      // Write the canary slot — content-level integrity proof checked
      // on every query (epoch only sees bridge-internal launches;
      // foreign ctxs clobber invisibly).
      const c = await tribhujSet(CANARY_SLOT, [...CANARY.toTrits()]);
      if (c.epoch !== undefined) this._epoch = c.epoch;
      this._pop = c.pop?.[0] ?? null;   // expected table size (incl. canary)
      this._stale = false;
      this._stats.syncs++;
      log.debug(`tribhuj sync: ${this._slots.size} slots in ${Date.now() - t0}ms`);
    } catch (err) {
      this._stale = true;
      this._up.ok = false;
      this._downUntil = Date.now() + PROBE_MS;
      throw err;
    }
  }

  _entryFor(peerId) {
    for (const bucket of this.table._buckets) {
      const e = bucket.get(peerId);
      if (e) return e;
    }
    return null;
  }

  // ── queries ──────────────────────────────────────────────────────

  /**
   * QUERY the resident table against the node's own address — returns
   * slot → {tierDist, tritDist} for every valid slot, computed on-tile.
   * @returns {Promise<Array|null>} 256 u16-ish entries, null on failure
   */
  async _querySelf() {
    const resp = await tribhujQuery([...this.table.selfAddress.toTrits()]);
    // A foreign kernel launch clobbers the resident table without
    // dropping the bridge — from the bridge's own ops (epoch mismatch)
    // AND from other hw contexts on the partition (epoch can't see
    // them). The canary row is the content proof: tile-reported
    // distance for slot 255 must equal the host-computed value.
    const target = this.table.selfAddress;
    const row = resp.tiles[0][CANARY_SLOT];
    const epochBad = this._epoch !== null && resp.epoch !== undefined &&
                     resp.epoch !== this._epoch;
    const canaryBad = row === INVALID ||
      (row & 0xFF) !== CANARY.tritDistance(target).distance ||
      ((row >> 8) & 0xFF) !== CANARY.tierDistance(target);
    if (epochBad || canaryBad) {
      this._stale = true;
      this._stats.errors++;
      log.debug(`tribhuj table clobbered (${epochBad ? 'epoch' : 'canary'}` +
                ' mismatch) — resyncing');
      this._probe();
      return null;
    }
    this._stats.queries++;
    return resp.tiles[0];       // all tiles hold identical tables
  }

  /**
   * NPU-driven diverse selection — the distance math runs on-tile.
   * Same semantics as TernaryRoutingTable.selectDiverse.
   * @returns {Promise<string[]|null>} picks, or null when not ready
   */
  async selectDiverse(peerIds, count) {
    if (!this.ready) return null;
    try {
      const slots = await this._querySelf();
      if (!slots) return null;

      const byTier = [[], [], []];
      const unscored = [];
      for (const id of peerIds) {
        const s = this._slots.get(id);
        const e = s === undefined ? INVALID : slots[s];
        const tier = e === INVALID ? 0 : (e >> 8) & 0xFF;
        if (tier >= 1 && tier <= TIER_COUNT) byTier[tier - 1].push(id);
        else unscored.push(id);
      }

      const picks = [];
      const cursors = [0, 0, 0];
      while (picks.length < count) {
        let added = false;
        for (let t = TIER_COUNT - 1; t >= 0; t--) {
          if (cursors[t] < byTier[t].length) {
            picks.push(byTier[t][cursors[t]++]);
            added = true;
            if (picks.length >= count) break;
          }
        }
        if (!added) break;
      }
      for (const id of unscored) {
        if (picks.length >= count) break;
        picks.push(id);
      }
      this._stats.npuSelects++;
      return picks;
    } catch (err) {
      this._stats.errors++;
      log.debug(`tribhuj query failed: ${err.message}`);
      return null;
    }
  }

  /** TOPK nearest slots to a target address — for directed routing. */
  async topk(k, targetAddress) {
    if (!this.ready) return null;
    try {
      // topk results can't carry the canary — precheck pop instead: a
      // reinit (foreign launch, any ctx) drops tbl_pop off expected.
      if (this._pop !== null) {
        const p = await tribhujPop();
        if (p.pop?.[0] !== this._pop ||
            (this._epoch !== null && p.epoch !== undefined &&
             p.epoch !== this._epoch)) {
          this._stale = true;
          this._stats.errors++;
          log.debug('tribhuj pop/epoch mismatch on topk — resyncing');
          this._probe();
          return null;
        }
      }
      const resp = await tribhujTopk(k, [...targetAddress.toTrits()]);
      // Same epoch guard as _querySelf — clobbered table → resync, null
      if (this._epoch !== null && resp.epoch !== undefined &&
          resp.epoch !== this._epoch) {
        this._stale = true;
        this._stats.errors++;
        log.debug('tribhuj epoch mismatch on topk — resyncing');
        this._probe();
        return null;
      }
      // tile0 list of {slot,trit_dist,tier_dist} → peerIds
      return resp.tiles[0].map(e => {
        for (const [peerId, slot] of this._slots) {
          if (slot === e.slot) return { peerId, ...e };
        }
        return null;
      }).filter(Boolean);
    } catch {
      return null;
    }
  }

  /** Mirror/device status for telemetry. */
  get status() {
    return {
      ready: this.ready,
      up: this._up.ok,
      stale: this._stale,
      epoch: this._epoch,
      slots: this._slots.size,
      capacity: MAX_SLOTS,
      ...this._stats,
    };
  }
}

export default TribhujMirror;
