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
 * AGUWA Worker — Batch Kuramoto theta update on Worker thread.
 *
 * Receives SharedArrayBuffer from main thread (zero-copy).
 * Iterates active slots, reads theta via Atomics, computes e-weighted
 * Kuramoto coupling delta, writes updated theta back via Atomics.
 *
 * Main thread only writes theta when worker is NOT in-flight (boolean flag).
 * Worker only writes theta — main thread writes all other fields.
 * Int32 Atomics guarantees no torn reads. Kuramoto is inherently convergent,
 * so a stale theta is slightly less optimal, never a crash.
 *
 * @module mesh/aguwa-worker
 */

import { parentPort } from 'worker_threads';

// Slot layout (mirrors peer-phase-buffer.js)
const SLOT_SIZE_INT32 = 8;
const OFF_THETA = 0;
const OFF_STABILITY = 1;
const OFF_TIME_TRUST = 2;
const OFF_KARMA = 3;
const OFF_HARDWARE = 4;
const MICRO = 1_000_000;

parentPort.on('message', (msg) => {
    const {
        sharedBuffer,       // SharedArrayBuffer — primary
        overflowBuffer,     // SharedArrayBuffer | null — overflow
        primarySlots,       // number — slots in primary buffer
        activeSlots,        // number[] — absolute slot indices to process
        omega,              // number — natural frequency (rad/s)
        couplingConfig,     // { high, mid, low, min } — coupling strengths
        weights,            // { timeTrust, karma, hardware, stability } — AGUWA weights
        defaultCoupling,    // number — coupling to use for batch (conservative mid)
    } = msg;

    const primaryView = new Int32Array(sharedBuffer);
    const overflowView = overflowBuffer ? new Int32Array(overflowBuffer) : null;

    let totalDeltaRad = 0;
    let processed = 0;

    // Compute mean phase vector for coupling (batch approximation)
    let sumCos = 0, sumSin = 0;
    for (const slot of activeSlots) {
        const view = slot < primarySlots ? primaryView : overflowView;
        const base = (slot < primarySlots ? slot : slot - primarySlots) * SLOT_SIZE_INT32;
        const theta = Atomics.load(view, base + OFF_THETA) / MICRO;
        sumCos += Math.cos(theta);
        sumSin += Math.sin(theta);
    }
    const count = activeSlots.length;
    if (count === 0) {
        parentPort.postMessage({ totalDeltaMs: 0, slotsProcessed: 0 });
        return;
    }
    const meanTheta = Math.atan2(sumSin / count, sumCos / count);

    const K = defaultCoupling;

    for (const slot of activeSlots) {
        const view = slot < primarySlots ? primaryView : overflowView;
        const base = (slot < primarySlots ? slot : slot - primarySlots) * SLOT_SIZE_INT32;

        // Read peer state via Atomics
        const theta = Atomics.load(view, base + OFF_THETA) / MICRO;
        const timeTrust = Atomics.load(view, base + OFF_TIME_TRUST) / MICRO;
        const karma = Atomics.load(view, base + OFF_KARMA) / MICRO;
        const hardware = Atomics.load(view, base + OFF_HARDWARE) / MICRO;
        const stability = Atomics.load(view, base + OFF_STABILITY) / MICRO;

        // Compute AGUWA score: A_j = weighted sum
        const A_j =
            weights.timeTrust * timeTrust +
            weights.karma * karma +
            weights.hardware * hardware +
            weights.stability * stability;

        // Phase difference from mean
        let phaseDiff = theta - meanTheta;
        // Normalize to [-π, π]
        phaseDiff = ((phaseDiff + Math.PI) % (2 * Math.PI)) - Math.PI;
        if (phaseDiff < -Math.PI) phaseDiff += 2 * Math.PI;

        // e-weighted Kuramoto delta: K · A_j · e^{-|θ-ψ|} · sin(θ-ψ)
        const delta = K * A_j * Math.exp(-Math.abs(phaseDiff)) * Math.sin(phaseDiff);

        // Apply delta to theta
        let newTheta = theta + delta;
        // Normalize
        newTheta = ((newTheta + Math.PI) % (2 * Math.PI)) - Math.PI;
        if (newTheta < -Math.PI) newTheta += 2 * Math.PI;

        // Write updated theta back via Atomics
        Atomics.store(view, base + OFF_THETA, Math.round(newTheta * MICRO));

        totalDeltaRad += delta;
        processed++;
    }

    parentPort.postMessage({
        totalDeltaMs: (totalDeltaRad / (2 * Math.PI)) * 1000, // approximate ms correction
        slotsProcessed: processed,
    });
});
