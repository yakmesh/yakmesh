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
 * DNA Spiral wasm — native AVOTH/wormhole-seal math for the mesh.
 *
 * dna-spiral.wasm is the yakos-dna-spiral core compiled to wasm32
 * (scalar path — bit-exact with the AVX512 native build by design).
 * It is the SAME implementation the pq-bridge runs, carried in-process:
 * seal verification no longer defers to the bridge or to settlement.
 *
 * Flat ABI — no wasm-bindgen: a 4 KiB input buffer + 64-byte output
 * buffer exposed via exported pointers. NOTE: hashing allocates inside
 * wasm linear memory, which can grow and DETACH JS views — always
 * re-slice memory.buffer after a call.
 *
 * @module utils/dna-spiral
 * @license YakMesh-NE-1.0 (YAKMESH NETWORK ENGINE LICENSE AGREEMENT v1.0)
 * @copyright 2026 YAKMESH™ Contributors
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { createLogger } from './logger.js';

const log = createLogger('dna:spiral');
const WASM_PATH = fileURLToPath(new URL('./dna-spiral.wasm', import.meta.url));
const INPUT_CAP = 4096;

let _inst = null;
let _failed = false;

/** Lazily instantiate the wasm module; null if it can't load. */
function inst() {
  if (_inst || _failed) return _inst;
  try {
    const bytes = readFileSync(WASM_PATH);
    const mod = new WebAssembly.Module(bytes);
    _inst = new WebAssembly.Instance(mod, {});
  } catch (e) {
    _failed = true;
    log.warn('dna-spiral.wasm unavailable — seal math defers', { error: e.message });
  }
  return _inst;
}

function inp(ex) { return new Uint8Array(ex.exports.memory.buffer, ex.exports.input_ptr(), INPUT_CAP); }
function out(ex) { return new Uint8Array(ex.exports.memory.buffer, ex.exports.output_ptr(), 64); }

/**
 * Derive a wormhole seal: first 4 quats of AVOTH(nodeId ‖ jobId ‖ epoch).
 * @param {string} nodeIdHex - 64-char hex
 * @param {string} jobIdHex - 64-char hex ('00…00' for epoch seals)
 * @param {number} epoch
 * @returns {number[]|null} 4 quats, or null when wasm is unavailable
 */
export function sealDerive(nodeIdHex, jobIdHex, epoch) {
  const ex = inst();
  if (!ex) return null;
  const i = inp(ex);
  i.fill(0, 0, 64);
  i.set(Buffer.from(nodeIdHex, 'hex'), 0);
  i.set(Buffer.from(jobIdHex, 'hex'), 32);
  ex.exports.seal_derive(epoch >>> 0);
  return [...out(ex).slice(0, 4)];
}

/**
 * Consensus check — does `seal` equal derive(nodeId ‖ ZERO ‖ epoch)?
 * Returns null when wasm is unavailable (caller defers), never guesses.
 */
export function verifyEpochSeal(nodeIdHex, epoch, seal) {
  const d = sealDerive(nodeIdHex, '0'.repeat(64), epoch);
  if (d === null) return null;
  return d.length === seal.length && d.every((q, i) => q === seal[i]);
}

/**
 * AVOTH-256 of arbitrary bytes → Buffer(64), or null when unavailable.
 */
export function avothHash(data) {
  const ex = inst();
  if (!ex || data.length > INPUT_CAP) return null;
  inp(ex).set(data);
  const n = ex.exports.avoth_hash(data.length);
  return n === 64 ? Buffer.from(out(ex).slice(0, 64)) : null;
}

/** True when the wasm module is loaded — diagnostic, not a gate. */
export function isAvailable() {
  return inst() !== null;
}
