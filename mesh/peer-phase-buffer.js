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
 * PeerPhaseBuffer — SharedArrayBuffer-backed peer state for AGUWA Kuramoto sync.
 *
 * Hot-path numeric fields (theta, scores, timestamps, flags) are stored in a
 * contiguous SharedArrayBuffer using Int32 with fixed-point quantization.
 * Enables zero-copy Worker handoff for batch Kuramoto computation (Phase 5).
 *
 * Layout: 32 bytes per peer slot (cache-line friendly on both Intel and AMD).
 * | Offset | Size | Field           | Quantization                          |
 * |--------|------|-----------------|---------------------------------------|
 * | 0      | 4B   | theta           | microrads (×1,000,000) — Int32        |
 * | 4      | 4B   | stabilityScore  | micro-units (×1,000,000) — Int32      |
 * | 8      | 4B   | timeTrust       | micro-units (×1,000,000) — Int32      |
 * | 12     | 4B   | karmaScore      | micro-units (×1,000,000) — Int32      |
 * | 16     | 4B   | hardwareScore   | micro-units (×1,000,000) — Int32      |
 * | 20     | 4B   | lastArrivalLow  | lower 32 bits of Unix ms (Int32)      |
 * | 24     | 4B   | lastArrivalHigh | upper 32 bits of Unix ms (Int32)      |
 * | 28     | 4B   | flags           | bits 0-1: admission, 2: stale         |
 *
 * @module PeerPhaseBuffer
 */

import { createLogger } from '../utils/logger.js';

const log = createLogger('mesh:phase-buffer');

// ═══════════════════════════════════════════════════════════
// Slot layout constants
// ═══════════════════════════════════════════════════════════
const SLOT_SIZE_BYTES = 32;
const SLOT_SIZE_INT32 = SLOT_SIZE_BYTES / 4; // 8 Int32s per slot

// Field offsets (in Int32 units, not bytes)
const OFF_THETA = 0;
const OFF_STABILITY = 1;
const OFF_TIME_TRUST = 2;
const OFF_KARMA = 3;
const OFF_HARDWARE = 4;
const OFF_ARRIVAL_LO = 5;
const OFF_ARRIVAL_HI = 6;
const OFF_FLAGS = 7;

// Fixed-point scale factor: float ↔ Int32
const MICRO = 1_000_000;

// Admission state encoding in flags bits 0-1
export const ADMISSION_AFFIRM = 1;   // +1
export const ADMISSION_ABSTAIN = 0;  //  0
export const ADMISSION_DENY = 2;     // -1 (encoded as 2 to fit 2 bits unsigned)
const FLAG_STALE = 1 << 2;          // bit 2

// Capacity formula constants
const BASE_PEERS = 64;
const RECALC_COOLDOWN_MS = 2000;

// ═══════════════════════════════════════════════════════════
// Dynamic capacity formula
// ═══════════════════════════════════════════════════════════

/**
 * Compute max peers from hardware telemetry.
 * maxPeers = floor(basePeers × hardwareMultiplier)
 *
 * Runtime multipliers (network, time) are applied in recalculateCapacity().
 *
 * @param {{ threads?: number, totalTops?: number }} hw
 * @returns {number}
 */
function computeBaseCapacity(hw) {
    const threads = hw?.threads || 4;
    const tops = hw?.totalTops || 0;

    // Hardware multiplier: more threads and compute = more peers
    const hwMul = Math.max(1, Math.log2(threads + 1) + Math.log2(tops + 1) * 0.5);

    return Math.floor(BASE_PEERS * hwMul);
}

// ═══════════════════════════════════════════════════════════
// PeerPhaseBuffer
// ═══════════════════════════════════════════════════════════

export class PeerPhaseBuffer {
    /** @type {SharedArrayBuffer} Primary buffer */
    #primary;
    /** @type {Int32Array} Primary view */
    #primaryView;
    /** @type {number} Max slots in primary */
    #primarySlots;

    /** @type {SharedArrayBuffer|null} Overflow buffer (allocated on demand) */
    #overflow = null;
    /** @type {Int32Array|null} Overflow view */
    #overflowView = null;
    /** @type {number} Max slots in overflow */
    #overflowSlots = 0;

    /** @type {Map<string, number>} nodeId → slotIndex */
    #slotMap = new Map();
    /** @type {number[]} Stack of free primary slot indices */
    #freeSlots = [];
    /** @type {number[]} Stack of free overflow slot indices */
    #freeOverflow = [];

    /** @type {number} Base capacity from HW (before runtime multipliers) */
    #baseMaxPeers;
    /** @type {number} Effective max peers (after runtime multipliers) */
    #maxPeers;

    /** @type {number} Network jitter multiplier [0, 1] */
    #networkMultiplier = 1.0;
    /** @type {number} Time order multiplier */
    #timeMultiplier = 1.0;

    /** @type {number} Timestamp of last recalculation */
    #lastRecalcMs = 0;

    /**
     * @param {{ threads?: number, totalTops?: number }} hwTelemetry
     */
    constructor(hwTelemetry) {
        this.#baseMaxPeers = computeBaseCapacity(hwTelemetry);
        this.#maxPeers = this.#baseMaxPeers;

        // Allocate primary buffer with 2× headroom
        this.#primarySlots = this.#baseMaxPeers * 2;
        this.#primary = new SharedArrayBuffer(this.#primarySlots * SLOT_SIZE_BYTES);
        this.#primaryView = new Int32Array(this.#primary);

        // Initialize free slot stack (fill from high to low so low indices are allocated first)
        for (let i = this.#primarySlots - 1; i >= 0; i--) {
            this.#freeSlots.push(i);
        }

        log.info('PeerPhaseBuffer allocated', {
            baseMaxPeers: this.#baseMaxPeers,
            primarySlots: this.#primarySlots,
            bytesAllocated: this.#primarySlots * SLOT_SIZE_BYTES,
        });
    }

    // ═════════════════════════════════════════════════════════
    // Slot lifecycle
    // ═════════════════════════════════════════════════════════

    /**
     * Allocate a slot for a peer.
     * @param {string} nodeId
     * @returns {number} Slot index, or -1 if both buffers full
     */
    allocateSlot(nodeId) {
        if (this.#slotMap.has(nodeId)) {
            return this.#slotMap.get(nodeId);
        }

        let slotIdx;

        if (this.#freeSlots.length > 0) {
            // Primary buffer has space
            slotIdx = this.#freeSlots.pop();
        } else if (this.#overflow !== null && this.#freeOverflow.length > 0) {
            // Overflow buffer has space
            slotIdx = this.#primarySlots + this.#freeOverflow.pop();
        } else if (this.#overflow === null) {
            // Primary full, no overflow yet — allocate overflow
            this.#allocateOverflow();
            if (this.#freeOverflow.length > 0) {
                slotIdx = this.#primarySlots + this.#freeOverflow.pop();
            } else {
                return -1; // Shouldn't happen — overflow just allocated
            }
        } else {
            // Both full
            log.warn('PeerPhaseBuffer: all slots exhausted (primary + overflow)');
            return -1;
        }

        this.#slotMap.set(nodeId, slotIdx);

        // Zero the slot
        const view = this.#viewFor(slotIdx);
        const base = this.#baseFor(slotIdx);
        for (let i = 0; i < SLOT_SIZE_INT32; i++) {
            Atomics.store(view, base + i, 0);
        }

        return slotIdx;
    }

    /**
     * Free a peer's slot.
     * @param {string} nodeId
     */
    freeSlot(nodeId) {
        const idx = this.#slotMap.get(nodeId);
        if (idx === undefined) return;

        this.#slotMap.delete(nodeId);

        if (idx < this.#primarySlots) {
            this.#freeSlots.push(idx);
        } else {
            this.#freeOverflow.push(idx - this.#primarySlots);
        }
    }

    /**
     * Check if a nodeId has an allocated slot.
     * @param {string} nodeId
     * @returns {boolean}
     */
    hasSlot(nodeId) {
        return this.#slotMap.has(nodeId);
    }

    /**
     * Get slot index for a nodeId.
     * @param {string} nodeId
     * @returns {number|undefined}
     */
    getSlotIndex(nodeId) {
        return this.#slotMap.get(nodeId);
    }

    // ═════════════════════════════════════════════════════════
    // Field accessors (Atomics.load / Atomics.store)
    // ═════════════════════════════════════════════════════════

    /** @returns {number} theta in radians */
    getTheta(slot) {
        return Atomics.load(this.#viewFor(slot), this.#baseFor(slot) + OFF_THETA) / MICRO;
    }
    setTheta(slot, radians) {
        Atomics.store(this.#viewFor(slot), this.#baseFor(slot) + OFF_THETA,
            Math.round(radians * MICRO));
    }

    /** @returns {number} stability score [0, 1] */
    getStabilityScore(slot) {
        return Atomics.load(this.#viewFor(slot), this.#baseFor(slot) + OFF_STABILITY) / MICRO;
    }
    setStabilityScore(slot, score) {
        Atomics.store(this.#viewFor(slot), this.#baseFor(slot) + OFF_STABILITY,
            Math.round(score * MICRO));
    }

    /** @returns {number} time trust [0, 1] */
    getTimeTrust(slot) {
        return Atomics.load(this.#viewFor(slot), this.#baseFor(slot) + OFF_TIME_TRUST) / MICRO;
    }
    setTimeTrust(slot, score) {
        Atomics.store(this.#viewFor(slot), this.#baseFor(slot) + OFF_TIME_TRUST,
            Math.round(score * MICRO));
    }

    /** @returns {number} karma score [0, 1] */
    getKarmaScore(slot) {
        return Atomics.load(this.#viewFor(slot), this.#baseFor(slot) + OFF_KARMA) / MICRO;
    }
    setKarmaScore(slot, score) {
        Atomics.store(this.#viewFor(slot), this.#baseFor(slot) + OFF_KARMA,
            Math.round(score * MICRO));
    }

    /** @returns {number} hardware score [0, 1] */
    getHardwareScore(slot) {
        return Atomics.load(this.#viewFor(slot), this.#baseFor(slot) + OFF_HARDWARE) / MICRO;
    }
    setHardwareScore(slot, score) {
        Atomics.store(this.#viewFor(slot), this.#baseFor(slot) + OFF_HARDWARE,
            Math.round(score * MICRO));
    }

    /** @returns {number} last arrival timestamp in ms */
    getLastArrival(slot) {
        const view = this.#viewFor(slot);
        const base = this.#baseFor(slot);
        const lo = Atomics.load(view, base + OFF_ARRIVAL_LO);
        const hi = Atomics.load(view, base + OFF_ARRIVAL_HI);
        // Reconstruct uint64 from two int32s (safe for ~292 million years of ms)
        return (hi >>> 0) * 0x100000000 + (lo >>> 0);
    }
    setLastArrival(slot, ms) {
        const view = this.#viewFor(slot);
        const base = this.#baseFor(slot);
        Atomics.store(view, base + OFF_ARRIVAL_LO, ms & 0xFFFFFFFF);
        Atomics.store(view, base + OFF_ARRIVAL_HI, (ms / 0x100000000) | 0);
    }

    /** @returns {number} raw flags int32 */
    getFlags(slot) {
        return Atomics.load(this.#viewFor(slot), this.#baseFor(slot) + OFF_FLAGS);
    }
    setFlags(slot, flags) {
        Atomics.store(this.#viewFor(slot), this.#baseFor(slot) + OFF_FLAGS, flags);
    }

    /** Get admission state from flags */
    getAdmissionState(slot) {
        const bits = this.getFlags(slot) & 0x3;
        if (bits === ADMISSION_DENY) return -1;
        if (bits === ADMISSION_AFFIRM) return 1;
        return 0; // ABSTAIN
    }

    /** Set admission state in flags (preserves other bits) */
    setAdmissionState(slot, state) {
        const encoded = state === -1 ? ADMISSION_DENY : (state === 1 ? ADMISSION_AFFIRM : ADMISSION_ABSTAIN);
        const current = this.getFlags(slot);
        this.setFlags(slot, (current & ~0x3) | encoded);
    }

    /** Check/set stale bit */
    isStale(slot) {
        return (this.getFlags(slot) & FLAG_STALE) !== 0;
    }
    setStale(slot, stale) {
        const current = this.getFlags(slot);
        this.setFlags(slot, stale ? (current | FLAG_STALE) : (current & ~FLAG_STALE));
    }

    // ═════════════════════════════════════════════════════════
    // Capacity management (Phase 2 — event-driven recalc)
    // ═════════════════════════════════════════════════════════

    /**
     * Recalculate effective maxPeers from runtime conditions.
     * Rate-limited to prevent thrashing during burst connections.
     *
     * @param {number} networkJitter - Current jitter estimate [0, 1]
     * @param {number} orderParameter - Kuramoto order parameter [0, 1]
     * @returns {boolean} true if maxPeers changed
     */
    recalculateCapacity(networkJitter = 0, orderParameter = 1) {
        const now = Date.now();
        if (now - this.#lastRecalcMs < RECALC_COOLDOWN_MS) return false;
        this.#lastRecalcMs = now;

        // Network multiplier: high jitter → fewer peers
        this.#networkMultiplier = Math.max(0.3, 1 - networkJitter * 0.5);

        // Time multiplier from order parameter health bands
        if (orderParameter >= 0.9) this.#timeMultiplier = 1.2;
        else if (orderParameter >= 0.5) this.#timeMultiplier = 1.0;
        else if (orderParameter >= 0.2) this.#timeMultiplier = 0.6;
        else this.#timeMultiplier = 0.3;

        const oldMax = this.#maxPeers;
        this.#maxPeers = Math.floor(
            this.#baseMaxPeers * this.#networkMultiplier * this.#timeMultiplier
        );
        // Never go below 4 peers (mesh needs minimum connectivity)
        this.#maxPeers = Math.max(4, this.#maxPeers);

        if (oldMax !== this.#maxPeers) {
            log.debug('Capacity recalculated', {
                oldMax, newMax: this.#maxPeers,
                networkMul: this.#networkMultiplier.toFixed(2),
                timeMul: this.#timeMultiplier.toFixed(1),
            });
            return true;
        }
        return false;
    }

    // ═════════════════════════════════════════════════════════
    // Buffer status
    // ═════════════════════════════════════════════════════════

    /** Current number of allocated peer slots */
    get peerCount() { return this.#slotMap.size; }

    /** Effective max peers (after runtime multipliers) */
    get maxPeers() { return this.#maxPeers; }

    /** Base max peers (hardware only, no runtime multipliers) */
    get baseMaxPeers() { return this.#baseMaxPeers; }

    /** Total slots available (primary + overflow) */
    get totalSlots() { return this.#primarySlots + this.#overflowSlots; }

    /** Buffer utilization ratio */
    get utilization() { return this.peerCount / this.totalSlots; }

    /** Whether overflow buffer has been allocated */
    get hasOverflow() { return this.#overflow !== null; }

    /** Get the primary SharedArrayBuffer (for Worker handoff) */
    getSharedBuffer() { return this.#primary; }

    /** Get the overflow SharedArrayBuffer, if any (for Worker handoff) */
    getOverflowBuffer() { return this.#overflow; }

    /** Number of primary slots */
    get primarySlotCount() { return this.#primarySlots; }

    /** Number of overflow slots */
    get overflowSlotCount() { return this.#overflowSlots; }

    /** Iterator over [nodeId, slotIndex] entries */
    entries() { return this.#slotMap.entries(); }

    /** Get all active slot indices */
    activeSlots() { return [...this.#slotMap.values()]; }

    /** Get nodeId for a slot index (reverse lookup) */
    nodeIdForSlot(slot) {
        for (const [nodeId, idx] of this.#slotMap) {
            if (idx === slot) return nodeId;
        }
        return null;
    }

    // ═════════════════════════════════════════════════════════
    // Internal helpers
    // ═════════════════════════════════════════════════════════

    /** Get the Int32Array view for a given absolute slot index */
    #viewFor(slot) {
        return slot < this.#primarySlots ? this.#primaryView : this.#overflowView;
    }

    /** Get the base offset (in Int32 units) within the view for a given slot */
    #baseFor(slot) {
        return (slot < this.#primarySlots ? slot : slot - this.#primarySlots) * SLOT_SIZE_INT32;
    }

    /** Allocate overflow buffer (Phase 6) */
    #allocateOverflow() {
        this.#overflowSlots = Math.ceil(this.#primarySlots * 0.5);
        this.#overflow = new SharedArrayBuffer(this.#overflowSlots * SLOT_SIZE_BYTES);
        this.#overflowView = new Int32Array(this.#overflow);

        for (let i = this.#overflowSlots - 1; i >= 0; i--) {
            this.#freeOverflow.push(i);
        }

        log.warn('PeerPhaseBuffer overflow: primary buffer full, using overflow segment', {
            overflowSlots: this.#overflowSlots,
            totalSlots: this.totalSlots,
        });
    }
}

export default PeerPhaseBuffer;
