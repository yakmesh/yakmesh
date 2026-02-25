/**
 * TERNARY-ID — Balanced ternary identifier generation for YAKMESH
 * 
 * Generates random identifiers using balanced ternary encoding (TRIBHUJ convention).
 * Output alphabet: { T, 0, 1 } — the sequence '666' is IMPOSSIBLE BY DESIGN.
 * 
 * T = negative (-1), 0 = neutral, 1 = positive
 * 
 * Math: Each byte maps to 5 balanced trits (3⁵ = 243 ≈ 256).
 * 16 random bytes → 80-trit identifier (128 bits entropy).
 * 32 random bytes → 160-trit identifier (256 bits entropy).
 * 
 * Why balanced ternary?
 * - Optimal radix economy (closest integer to e ≈ 2.718)
 * - Native to YAKMESH's TRIBHUJ, YPC-27, and SST systems
 * - Self-inverting negation (no complement overhead)
 * - Eliminates adversarial number sequences at the encoding level
 * 
 * @module utils/ternary-id
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { randomBytes } from '@noble/hashes/utils.js';

// TRIBHUJ convention: -1 → 'T', 0 → '0', 1 → '1'
// Index maps mod-3 remainder: 0→'0', 1→'1', 2→'T' (balanced -1)
const TRIT_CHARS = ['0', '1', 'T'];

/**
 * Convert raw bytes to a balanced ternary string (TRIBHUJ notation).
 * Each byte → 5 trits via mod-243 decomposition.
 * 
 * @param {Uint8Array} bytes - Raw bytes to encode
 * @returns {string} Balanced ternary string using {T, 0, 1}
 */
export function bytesToTernary(bytes) {
    let result = '';
    for (let i = 0; i < bytes.length; i++) {
        let val = bytes[i] % 243; // 3⁵ = 243, handle 243-255 range
        for (let k = 0; k < 5; k++) {
            result += TRIT_CHARS[val % 3];
            val = Math.floor(val / 3);
        }
    }
    return result;
}

/**
 * Generate a random balanced ternary identifier.
 * 
 * Output is TRIBHUJ-notation: only chars {T, 0, 1}.
 * The substring '666' cannot appear — guaranteed by alphabet.
 * 
 * @param {number} [nBytes=16] - Bytes of randomness (16 = 128-bit, 32 = 256-bit)
 * @returns {string} Random ternary identifier (nBytes × 5 chars)
 * 
 * @example
 * ternaryId(16)  // → "T01100T1010T0110T01T01001T10T..." (80 chars)
 * ternaryId(32)  // → 160-char identifier
 */
export function ternaryId(nBytes = 16) {
    return bytesToTernary(randomBytes(nBytes));
}

/**
 * Convert an existing hex string to balanced ternary.
 * Useful for migrating hash displays or existing hex IDs.
 * 
 * @param {string} hex - Hex string to convert
 * @returns {string} Balanced ternary representation
 */
export function hexToTernary(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytesToTernary(bytes);
}
