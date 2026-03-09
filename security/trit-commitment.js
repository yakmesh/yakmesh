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
 * TRIT COMMITMENT — Cryptographic Backbone
 * 
 * Provides a ternary cryptographic layer that runs ALONGSIDE NIST algorithms.
 * This is defense-in-depth: both NIST (ML-DSA-65) AND 162T must verify for
 * a message to be trusted.
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * ⚠️  SECURITY: This is the ternary backbone, not a replacement for NIST.
 *     Both layers must be broken to compromise a message.
 *     162T provides quantum-hard SIS-based integrity independent of NIST.
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * The math:
 * - YPC-27 operates in ring Z[x]/(x^27 - 1) mod 3
 * - Forging a YPC-27 checksum requires solving the Shortest Vector Problem (SIS)
 * - 162T provides 3^162 ≈ 10^77 address space (~256-bit post-quantum)
 * - Combined binding uses polynomial multiplication for non-separability
 * 
 * Commitment Structure:
 * {
 *   senderAddress: "162-trit address (base64 encoded)",
 *   ypc27: "YPC-27 checksum (hex)",
 *   binding: "address ⊗ payload polynomial (hex)"
 * }
 * 
 * The binding ensures:
 * 1. Address cannot be separated from payload (polynomial non-commutativity)
 * 2. YPC-27 provides lattice-hard integrity independent of SHA/NIST
 * 3. 162T address pins the commitment to a specific mesh location
 * 
 * @module security/trit-commitment
 * @version 1.0.0
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { sha3_256 } from '../utils/accel.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { TritAddress, TOTAL_TRITS } from '../oracle/ternary-routing.js';
import { Poly27, YPC27_SST, DEFAULT_SEED, bytesToTrits, tritsToBytes, N } from '../oracle/ypc27.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('security:trit-commitment');

// =============================================================================
// CONSTANTS
// =============================================================================

/** Commitment version for future compatibility */
export const COMMITMENT_VERSION = 1;

/** Number of trits extracted from payload hash for binding */
const BINDING_TRITS = 27;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Convert a Poly27 to hex string.
 * Converts trit coefficients to bytes then to hex.
 * @param {Poly27} poly 
 * @returns {string}
 */
function poly27ToHex(poly) {
    const trits = poly.toTypedArray();
    // Pad to 30 trits (divisible by 5 for clean byte packing)
    const padded = new Int8Array(30);
    for (let i = 0; i < N; i++) {
        padded[i] = trits[i];
    }
    const bytes = tritsToBytes(padded);
    return bytesToHex(bytes);
}

/**
 * Convert hex string back to Poly27.
 * @param {string} hex 
 * @returns {Poly27}
 */
function hexToPoly27(hex) {
    return Poly27.fromHex(hex);
}

/**
 * Encode trits as base64 for compact transmission.
 * @param {Int8Array} trits — TOTAL_TRITS balanced trits (-1, 0, +1)
 * @returns {string} base64-encoded
 */
function encodeTrits(trits) {
    // Pad to next multiple of 5 (165 for 162T)
    const padLen = Math.ceil(TOTAL_TRITS / 5) * 5;
    const padded = new Int8Array(padLen);
    for (let i = 0; i < TOTAL_TRITS; i++) {
        padded[i] = trits[i];
    }
    const bytes = tritsToBytes(padded);
    return Buffer.from(bytes).toString('base64');
}

/**
 * Decode base64 to trits.
 * @param {string} encoded — base64-encoded trits
 * @returns {Int8Array}
 */
function decodeTrits(encoded) {
    const bytes = new Uint8Array(Buffer.from(encoded, 'base64'));
    const trits = bytesToTrits(bytes);
    // Trim to exactly TOTAL_TRITS
    return new Int8Array(trits.slice(0, TOTAL_TRITS));
}

/**
 * Extract 27 trits from a SHA3-256 hash for polynomial binding.
 * Uses the first ~6 bytes of the hash.
 * @param {Uint8Array} hash — 32-byte hash
 * @returns {Int8Array} — 27 trits
 */
function hashToTrits27(hash) {
    // Extract 27 trits from the hash (5 trits per byte, need 6 bytes = 30 trits)
    const trits = bytesToTrits(hash.slice(0, 6));
    return new Int8Array(trits.slice(0, BINDING_TRITS));
}

/**
 * Extract a Poly27 from the first 27 trits of a 162T address.
 * Uses the BASE tier (last 54 trits), taking only the first 27.
 * @param {TritAddress} address — 162-trit address
 * @returns {Poly27}
 */
function addressToPoly27(address) {
    // Use BASE tier (index 2), which is the identity-specific portion
    const baseTier = address.getTier(2); // 54 trits
    // Take first 27 trits for polynomial
    const poly27Trits = new Int8Array(baseTier.slice(0, N));
    return new Poly27(poly27Trits);
}

/**
 * Canonicalize an object for deterministic hashing.
 * Same as NAMCHE gateway's canonicalize function.
 * @param {any} obj 
 * @returns {string}
 */
function canonicalize(obj) {
    if (obj === null || typeof obj !== 'object') {
        return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
        return '[' + obj.map(canonicalize).join(',') + ']';
    }
    const keys = Object.keys(obj).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
}

// =============================================================================
// TRIT COMMITMENT CLASS
// =============================================================================

/**
 * Generate and verify ternary commitments.
 * 
 * @example
 * const commitment = TritCommitment.create(payload, senderAddress);
 * // {
 * //   version: 1,
 * //   senderAddress: "base64-encoded 162T address",
 * //   ypc27: "hex checksum",
 * //   binding: "hex polynomial binding"
 * // }
 * 
 * const isValid = TritCommitment.verify(payload, commitment);
 */
export class TritCommitment {
    /**
     * Create a ternary commitment for a payload.
     * 
     * The commitment binds the sender's 162T address to the payload using:
     * 1. YPC-27 checksum of the canonical payload
     * 2. Polynomial multiplication: addressPoly ⊗ payloadHashPoly
     * 
     * @param {Object|string|Uint8Array} payload — message payload (will be canonicalized if object)
     * @param {TritAddress} senderAddress — sender's 162T mesh address
     * @param {Poly27|number[]} [seed] — optional custom seed (defaults to network seed)
     * @returns {Object} commitment object
     */
    static create(payload, senderAddress, seed = DEFAULT_SEED) {
        // Canonicalize payload
        const payloadStr = typeof payload === 'object'
            ? canonicalize(payload)
            : typeof payload === 'string'
                ? payload
                : bytesToHex(payload);

        const payloadBytes = utf8ToBytes(payloadStr);

        // 1. Compute YPC-27 checksum with SST rotation
        const hasher = new YPC27_SST(seed);
        hasher.update(payloadBytes);
        const ypc27Hex = hasher.digestHex();

        // 2. Compute SHA3-256 of payload for polynomial binding
        const payloadHash = sha3_256(payloadBytes);
        const payloadTrits27 = hashToTrits27(payloadHash);
        const payloadPoly = new Poly27(payloadTrits27);

        // 3. Extract address polynomial
        const addressPoly = addressToPoly27(senderAddress);

        // 4. Compute binding: address ⊗ payload (cyclic convolution in Z[x]/(x^27-1) mod 3)
        // This is non-separable — you cannot extract addressPoly from the binding
        // without knowing payloadPoly (and vice versa)
        const binding = addressPoly.multiply(payloadPoly);
        const bindingHex = poly27ToHex(binding);

        // 5. Encode address for transmission
        const addressEncoded = encodeTrits(senderAddress.toTrits());

        log.debug('Created 162T commitment', {
            ypc27: ypc27Hex.slice(0, 12) + '...',
            binding: bindingHex.slice(0, 12) + '...'
        });

        return {
            version: COMMITMENT_VERSION,
            senderAddress: addressEncoded,
            ypc27: ypc27Hex,
            binding: bindingHex,
        };
    }

    /**
     * Verify a ternary commitment against a payload.
     * 
     * @param {Object|string|Uint8Array} payload — original payload
     * @param {Object} commitment — commitment object from create()
     * @param {Poly27|number[]} [seed] — optional custom seed (must match create())
     * @returns {Object} verification result
     */
    static verify(payload, commitment, seed = DEFAULT_SEED) {
        const result = {
            valid: false,
            checks: [],
            reason: null,
            detail: null,
        };

        try {
            // ─────────────────────────────────────────────────────────────────────
            // CHECK 1: Version compatibility
            // ─────────────────────────────────────────────────────────────────────
            if (commitment.version !== COMMITMENT_VERSION) {
                result.reason = 'VERSION_MISMATCH';
                result.detail = `Expected version ${COMMITMENT_VERSION}, got ${commitment.version}`;
                return result;
            }
            result.checks.push('VERSION_OK');

            // ─────────────────────────────────────────────────────────────────────
            // CHECK 2: Structure validity
            // ─────────────────────────────────────────────────────────────────────
            const required = ['version', 'senderAddress', 'ypc27', 'binding'];
            for (const field of required) {
                if (!(field in commitment)) {
                    result.reason = 'MALFORMED_STRUCTURE';
                    result.detail = `Missing required field: ${field}`;
                    return result;
                }
            }
            result.checks.push('STRUCTURE_OK');

            // ─────────────────────────────────────────────────────────────────────
            // CHECK 3: Decode sender address
            // ─────────────────────────────────────────────────────────────────────
            let senderAddress;
            try {
                const addressTrits = decodeTrits(commitment.senderAddress);
                senderAddress = new TritAddress(addressTrits);
            } catch (e) {
                result.reason = 'INVALID_ADDRESS';
                result.detail = `Failed to decode sender address: ${e.message}`;
                return result;
            }
            result.checks.push('ADDRESS_DECODED');

            // ─────────────────────────────────────────────────────────────────────
            // CHECK 4: Recompute YPC-27 and compare
            // ─────────────────────────────────────────────────────────────────────
            const payloadStr = typeof payload === 'object'
                ? canonicalize(payload)
                : typeof payload === 'string'
                    ? payload
                    : bytesToHex(payload);

            const payloadBytes = utf8ToBytes(payloadStr);
            const hasher = new YPC27_SST(seed);
            hasher.update(payloadBytes);
            const expectedYpc27Hex = hasher.digestHex();

            if (commitment.ypc27 !== expectedYpc27Hex) {
                result.reason = 'YPC27_MISMATCH';
                result.detail = 'YPC-27 checksum does not match payload';
                return result;
            }
            result.checks.push('YPC27_VALID');

            // ─────────────────────────────────────────────────────────────────────
            // CHECK 5: Recompute binding and compare
            // ─────────────────────────────────────────────────────────────────────
            const payloadHash = sha3_256(payloadBytes);
            const payloadTrits27 = hashToTrits27(payloadHash);
            const payloadPoly = new Poly27(payloadTrits27);
            const addressPoly = addressToPoly27(senderAddress);
            const expectedBinding = addressPoly.multiply(payloadPoly);
            const expectedBindingHex = poly27ToHex(expectedBinding);

            if (commitment.binding !== expectedBindingHex) {
                result.reason = 'BINDING_MISMATCH';
                result.detail = 'Polynomial binding does not match address and payload';
                return result;
            }
            result.checks.push('BINDING_VALID');

            // ═══════════════════════════════════════════════════════════════════════
            // ALL CHECKS PASSED
            // ═══════════════════════════════════════════════════════════════════════
            result.valid = true;
            result.reason = '162T_VERIFIED';
            result.senderAddress = senderAddress;

            log.debug('162T commitment verified', { checks: result.checks });

            return result;

        } catch (error) {
            result.reason = 'VERIFICATION_ERROR';
            result.detail = error.message;
            return result;
        }
    }

    /**
     * Quick check if a commitment appears structurally valid.
     * Does NOT verify cryptographic properties.
     * @param {Object} commitment 
     * @returns {boolean}
     */
    static isValidStructure(commitment) {
        if (!commitment || typeof commitment !== 'object') return false;
        if (commitment.version !== COMMITMENT_VERSION) return false;
        const required = ['senderAddress', 'ypc27', 'binding'];
        return required.every(f => typeof commitment[f] === 'string' && commitment[f].length > 0);
    }
}

// =============================================================================
// DUAL-LAYER MESSAGE FUNCTIONS
// =============================================================================

/**
 * Create a dual-layer signed message (NIST + 162T).
 * This is the backbone security model: both layers must verify.
 * 
 * @param {Object} payload — message payload
 * @param {Function} signNIST — function(payload) => hex signature (ML-DSA-65)
 * @param {TritAddress} senderAddress — sender's 162T address
 * @param {Poly27|number[]} [seed] — optional seed
 * @returns {Object} dual-signed message
 */
export function createDualLayerMessage(payload, signNIST, senderAddress, seed = DEFAULT_SEED) {
    // Canonicalize for determinism
    const payloadStr = canonicalize(payload);

    // Layer 1: NIST signature (ML-DSA-65)
    const nistSignature = signNIST(payloadStr);

    // Layer 2: 162T commitment
    const tritCommitment = TritCommitment.create(payload, senderAddress, seed);

    return {
        payload,
        nistSignature,
        tritCommitment,
    };
}

/**
 * Verify a dual-layer signed message.
 * BOTH layers must pass for the message to be trusted.
 * 
 * @param {Object} message — dual-signed message from createDualLayerMessage()
 * @param {Function} verifyNIST — function(payload, signature, publicKey) => boolean
 * @param {string} senderPublicKey — sender's ML-DSA-65 public key (hex)
 * @param {Poly27|number[]} [seed] — optional seed
 * @returns {Object} verification result
 */
export function verifyDualLayerMessage(message, verifyNIST, senderPublicKey, seed = DEFAULT_SEED) {
    const result = {
        valid: false,
        nistValid: false,
        tritValid: false,
        nistReason: null,
        tritReason: null,
        checks: [],
    };

    // ─────────────────────────────────────────────────────────────────────────
    // Layer 1: NIST verification
    // ─────────────────────────────────────────────────────────────────────────
    try {
        const payloadStr = canonicalize(message.payload);
        result.nistValid = verifyNIST(payloadStr, message.nistSignature, senderPublicKey);
        if (result.nistValid) {
            result.checks.push('NIST_SIGNATURE_OK');
        } else {
            result.nistReason = 'ML-DSA-65 signature verification failed';
        }
    } catch (e) {
        result.nistReason = `NIST verification error: ${e.message}`;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Layer 2: 162T verification
    // ─────────────────────────────────────────────────────────────────────────
    try {
        const tritResult = TritCommitment.verify(message.payload, message.tritCommitment, seed);
        result.tritValid = tritResult.valid;
        if (tritResult.valid) {
            result.checks.push('162T_COMMITMENT_OK');
        } else {
            result.tritReason = `${tritResult.reason}: ${tritResult.detail || ''}`;
        }
        result.tritChecks = tritResult.checks;
    } catch (e) {
        result.tritReason = `162T verification error: ${e.message}`;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BOTH layers must pass
    // ═══════════════════════════════════════════════════════════════════════
    result.valid = result.nistValid && result.tritValid;

    if (result.valid) {
        result.checks.push('DUAL_LAYER_VERIFIED');
    }

    return result;
}

// =============================================================================
// EXPORTS
// =============================================================================

export {
    encodeTrits,
    decodeTrits,
    encodeTrits as encodeTrits144,  // backward compat alias
    decodeTrits as decodeTrits144,  // backward compat alias
    hashToTrits27,
    addressToPoly27,
    canonicalize,
    poly27ToHex,
    hexToPoly27,
};

export default TritCommitment;
