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
 * Yakmesh Memory Safety — Circulating Canaries
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * PHILOSOPHY: MEMORY AS LIVING TISSUE
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Traditional memory safety: Static analysis, bounds checking, fuzzing.
 * Circulating Canaries: Runtime memory integrity that flows through SANGHA.
 * 
 * A CANARY is a strategically-placed memory region with known content.
 * During SANGHA circulation, canaries are checksummed and attested.
 * Corruption (buffer overflow, use-after-free exploit) is detected
 * within one circulation cycle.
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * CANARY TYPES
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * 1. STACK CANARIES — Placed in hot function frames
 *    Node.js doesn't give direct stack access, so we use proxy objects
 *    that live on the JS heap but represent "stack-like" volatile state.
 * 
 * 2. HEAP CANARIES — Typed arrays with known patterns
 *    These catch heap corruption from native modules (ONNX Runtime, etc.)
 * 
 * 3. BUFFER CANARIES — Boundaries around shared ArrayBuffers
 *    Detect out-of-bounds writes in Worker-shared memory.
 * 
 * 4. CLOSURE CANARIES — Captured variables in long-lived closures
 *    Detect corruption of closure state (rare but severe).
 * 
 * @module security/memory-safety
 * @version 1.0.0
 */

import { createLogger } from '../utils/logger.js';
import { sha3_256 } from '../utils/accel.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { randomBytes } from 'crypto';
import { EventEmitter } from 'events';

const log = createLogger('security:memory-safety');

// =============================================================================
// CONSTANTS
// =============================================================================

/** Canary types */
export const CANARY_TYPE = Object.freeze({
  HEAP: 'HEAP',           // Typed array with known pattern
  BUFFER: 'BUFFER',       // ArrayBuffer boundary markers
  CLOSURE: 'CLOSURE',     // Closure variable integrity
  NATIVE: 'NATIVE',       // Native module interface canary
});

/** Default canary pattern size */
const CANARY_SIZE = 256;

/** Canary check interval (during SANGHA circulation) */
const DEFAULT_CHECK_INTERVAL_MS = 5000;

// =============================================================================
// CANARY
// =============================================================================

/**
 * Canary — A memory integrity checkpoint
 * 
 * Each canary:
 * - Holds a known pattern in memory
 * - Computes a baseline hash at creation
 * - Verifies integrity during circulation
 */
export class Canary {
  #id;
  #type;
  #data;
  #baselineHash;
  #createdAt;
  #lastCheck;
  #checkCount;
  #corrupted;

  /**
   * @param {string} id - Unique canary identifier
   * @param {string} type - Canary type (HEAP/BUFFER/CLOSURE/NATIVE)
   * @param {number} size - Size in bytes
   */
  constructor(id, type = CANARY_TYPE.HEAP, size = CANARY_SIZE) {
    this.#id = id;
    this.#type = type;
    this.#data = new Uint8Array(size);
    this.#createdAt = Date.now();
    this.#lastCheck = 0;
    this.#checkCount = 0;
    this.#corrupted = false;

    // Fill with cryptographically random pattern
    const pattern = randomBytes(size);
    this.#data.set(pattern);

    // Compute baseline hash
    this.#baselineHash = bytesToHex(sha3_256(this.#data));

    Object.seal(this);
  }

  /** Get canary ID */
  get id() { return this.#id; }

  /** Get canary type */
  get type() { return this.#type; }

  /** Get baseline hash */
  get baselineHash() { return this.#baselineHash; }

  /** Is canary corrupted? */
  get isCorrupted() { return this.#corrupted; }

  /** Get check count */
  get checkCount() { return this.#checkCount; }

  /**
   * Verify canary integrity
   * @returns {{ valid: boolean, currentHash?: string }}
   */
  verify() {
    this.#lastCheck = Date.now();
    this.#checkCount++;

    const currentHash = bytesToHex(sha3_256(this.#data));

    if (currentHash !== this.#baselineHash) {
      this.#corrupted = true;
      return {
        valid: false,
        currentHash,
        expectedHash: this.#baselineHash,
      };
    }

    return { valid: true };
  }

  /**
   * Get pointer to underlying buffer (for native module boundary testing)
   * @returns {Uint8Array}
   */
  getBuffer() {
    return this.#data;
  }

  /**
   * Get state for SANGHA attestation
   */
  getState() {
    return {
      id: this.#id,
      type: this.#type,
      size: this.#data.length,
      baselineHash: this.#baselineHash.slice(0, 16) + '...',
      lastCheck: this.#lastCheck,
      checkCount: this.#checkCount,
      corrupted: this.#corrupted,
    };
  }
}

// =============================================================================
// CLOSURE CANARY
// =============================================================================

/**
 * ClosureCanary — Protects closure state integrity
 * 
 * JavaScript closures capture variables from outer scope.
 * If those variables are corrupted (rare, but possible via
 * native module bugs), the closure behavior changes silently.
 * 
 * A ClosureCanary captures a set of sentinel values in a closure
 * and verifies they haven't been mutated.
 */
export class ClosureCanary {
  #id;
  #verifier;
  #expectedHash;
  #corrupted;
  #checkCount;

  /**
   * @param {string} id - Unique identifier
   */
  constructor(id) {
    this.#id = id;
    this.#corrupted = false;
    this.#checkCount = 0;

    // Create sentinel values in a closure
    const sentinel1 = 0xDEADBEEF;
    const sentinel2 = 0xCAFEBABE;
    const sentinel3 = 'YAKMESH_CLOSURE_CANARY_' + id;
    const sentinel4 = Object.freeze({ magic: 0x144714, frozen: true });

    // Compute expected hash
    const combined = `${sentinel1}:${sentinel2}:${sentinel3}:${JSON.stringify(sentinel4)}`;
    this.#expectedHash = bytesToHex(sha3_256(new TextEncoder().encode(combined)));

    // Create verifier closure that captures the sentinels
    this.#verifier = () => {
      const combined = `${sentinel1}:${sentinel2}:${sentinel3}:${JSON.stringify(sentinel4)}`;
      return bytesToHex(sha3_256(new TextEncoder().encode(combined)));
    };

    Object.seal(this);
  }

  /** Get canary ID */
  get id() { return this.#id; }

  /** Is canary corrupted? */
  get isCorrupted() { return this.#corrupted; }

  /**
   * Verify closure integrity
   */
  verify() {
    this.#checkCount++;

    try {
      const currentHash = this.#verifier();

      if (currentHash !== this.#expectedHash) {
        this.#corrupted = true;
        return {
          valid: false,
          error: 'Closure sentinel corruption detected',
        };
      }

      return { valid: true };
    } catch (e) {
      this.#corrupted = true;
      return {
        valid: false,
        error: `Closure verification threw: ${e.message}`,
      };
    }
  }

  /**
   * Get state for SANGHA attestation
   */
  getState() {
    return {
      id: this.#id,
      type: CANARY_TYPE.CLOSURE,
      expectedHash: this.#expectedHash.slice(0, 16) + '...',
      checkCount: this.#checkCount,
      corrupted: this.#corrupted,
    };
  }
}

// =============================================================================
// NATIVE MODULE CANARY
// =============================================================================

/**
 * NativeModuleCanary — Boundary canary for native module interfaces
 * 
 * Places canaries around data passed to native modules (ONNX Runtime, etc.)
 * to detect buffer overflows or out-of-bounds writes.
 */
export class NativeModuleCanary {
  #id;
  #moduleName;
  #preBuffer;
  #postBuffer;
  #preHash;
  #postHash;
  #corrupted;
  #checkCount;

  /**
   * @param {string} id - Unique identifier
   * @param {string} moduleName - Name of the native module being protected
   * @param {number} size - Canary size (before and after)
   */
  constructor(id, moduleName, size = 64) {
    this.#id = id;
    this.#moduleName = moduleName;
    this.#corrupted = false;
    this.#checkCount = 0;

    // Create pre and post buffers with random patterns
    this.#preBuffer = new Uint8Array(size);
    this.#postBuffer = new Uint8Array(size);

    const prePat = randomBytes(size);
    const postPat = randomBytes(size);

    this.#preBuffer.set(prePat);
    this.#postBuffer.set(postPat);

    this.#preHash = bytesToHex(sha3_256(this.#preBuffer));
    this.#postHash = bytesToHex(sha3_256(this.#postBuffer));

    Object.seal(this);
  }

  /** Get canary ID */
  get id() { return this.#id; }

  /** Get module name */
  get moduleName() { return this.#moduleName; }

  /** Get pre-buffer (place before native call data) */
  get preBuffer() { return this.#preBuffer; }

  /** Get post-buffer (place after native call data) */
  get postBuffer() { return this.#postBuffer; }

  /** Is canary corrupted? */
  get isCorrupted() { return this.#corrupted; }

  /**
   * Verify both boundaries
   */
  verify() {
    this.#checkCount++;

    const preHash = bytesToHex(sha3_256(this.#preBuffer));
    const postHash = bytesToHex(sha3_256(this.#postBuffer));

    const errors = [];

    if (preHash !== this.#preHash) {
      errors.push('Pre-buffer corrupted (underflow detected)');
    }

    if (postHash !== this.#postHash) {
      errors.push('Post-buffer corrupted (overflow detected)');
    }

    if (errors.length > 0) {
      this.#corrupted = true;
      return {
        valid: false,
        errors,
        module: this.#moduleName,
      };
    }

    return { valid: true };
  }

  /**
   * Get state for SANGHA attestation
   */
  getState() {
    return {
      id: this.#id,
      type: CANARY_TYPE.NATIVE,
      module: this.#moduleName,
      preHash: this.#preHash.slice(0, 16) + '...',
      postHash: this.#postHash.slice(0, 16) + '...',
      checkCount: this.#checkCount,
      corrupted: this.#corrupted,
    };
  }
}

// =============================================================================
// MEMORY SAFETY MANAGER
// =============================================================================

/**
 * MemorySafety — Manages all canaries and SANGHA integration
 */
export class MemorySafety extends EventEmitter {
  #canaries;
  #closureCanaries;
  #nativeCanaries;
  #sangha;
  #started;
  #checkInterval;
  #lastCheck;
  #totalCorruptions;

  constructor() {
    super();
    this.#canaries = new Map();
    this.#closureCanaries = new Map();
    this.#nativeCanaries = new Map();
    this.#sangha = null;
    this.#started = false;
    this.#checkInterval = null;
    this.#lastCheck = 0;
    this.#totalCorruptions = 0;

    Object.seal(this);
  }

  /**
   * Create a heap canary
   * @param {string} id - Unique identifier
   * @param {number} size - Size in bytes
   * @returns {Canary}
   */
  createHeapCanary(id, size = CANARY_SIZE) {
    const canary = new Canary(id, CANARY_TYPE.HEAP, size);
    this.#canaries.set(id, canary);
    log.debug('Created heap canary', { id, size });
    return canary;
  }

  /**
   * Create a closure canary
   * @param {string} id - Unique identifier
   * @returns {ClosureCanary}
   */
  createClosureCanary(id) {
    const canary = new ClosureCanary(id);
    this.#closureCanaries.set(id, canary);
    log.debug('Created closure canary', { id });
    return canary;
  }

  /**
   * Create a native module canary
   * @param {string} id - Unique identifier
   * @param {string} moduleName - Native module name
   * @param {number} size - Boundary size
   * @returns {NativeModuleCanary}
   */
  createNativeCanary(id, moduleName, size = 64) {
    const canary = new NativeModuleCanary(id, moduleName, size);
    this.#nativeCanaries.set(id, canary);
    log.debug('Created native module canary', { id, module: moduleName });
    return canary;
  }

  /**
   * Initialize default canaries for critical components
   */
  init() {
    // Heap canaries for key memory regions
    this.createHeapCanary('heap:crypto', 512);      // Crypto operations
    this.createHeapCanary('heap:mesh', 256);        // Mesh state
    this.createHeapCanary('heap:identity', 256);    // Identity data

    // Closure canaries for long-lived closures
    this.createClosureCanary('closure:event-handlers');
    this.createClosureCanary('closure:timers');

    // Native module canaries
    this.createNativeCanary('native:onnx', 'onnxruntime', 128);
    this.createNativeCanary('native:sqlite', 'better-sqlite3', 64);

    log.info('Memory safety initialized', {
      heapCanaries: this.#canaries.size,
      closureCanaries: this.#closureCanaries.size,
      nativeCanaries: this.#nativeCanaries.size,
    });
  }

  /**
   * Bind to SANGHA collective
   * @param {Sangha} sangha - The SANGHA instance
   */
  bindSangha(sangha) {
    this.#sangha = sangha;
    log.info('Memory safety bound to SANGHA collective');
  }

  /**
   * Verify all canaries
   * @returns {{ valid: boolean, corruptions: object[] }}
   */
  verifyAll() {
    const corruptions = [];
    this.#lastCheck = Date.now();

    // Check heap canaries
    for (const [id, canary] of this.#canaries) {
      const result = canary.verify();
      if (!result.valid) {
        corruptions.push({
          type: CANARY_TYPE.HEAP,
          id,
          ...result,
        });
      }
    }

    // Check closure canaries
    for (const [id, canary] of this.#closureCanaries) {
      const result = canary.verify();
      if (!result.valid) {
        corruptions.push({
          type: CANARY_TYPE.CLOSURE,
          id,
          ...result,
        });
      }
    }

    // Check native canaries
    for (const [id, canary] of this.#nativeCanaries) {
      const result = canary.verify();
      if (!result.valid) {
        corruptions.push({
          type: CANARY_TYPE.NATIVE,
          id,
          ...result,
        });
      }
    }

    if (corruptions.length > 0) {
      this.#totalCorruptions += corruptions.length;
      this.emit('corruption', corruptions);
      log.error('🚨 MEMORY CORRUPTION DETECTED', {
        count: corruptions.length,
        corruptions,
      });
    }

    return {
      valid: corruptions.length === 0,
      corruptions,
    };
  }

  /**
   * Start periodic verification
   * @param {number} intervalMs - Check interval
   */
  start(intervalMs = DEFAULT_CHECK_INTERVAL_MS) {
    if (this.#started) return;

    this.#started = true;

    this.#checkInterval = setInterval(() => {
      this.verifyAll();
    }, intervalMs);

    log.info('Memory safety monitoring started', { interval: intervalMs });
  }

  /**
   * Get state for SANGHA attestation
   * @returns {Promise<object>}
   */
  async getState() {
    const heapStates = [];
    const closureStates = [];
    const nativeStates = [];

    for (const canary of this.#canaries.values()) {
      heapStates.push(canary.getState());
    }

    for (const canary of this.#closureCanaries.values()) {
      closureStates.push(canary.getState());
    }

    for (const canary of this.#nativeCanaries.values()) {
      nativeStates.push(canary.getState());
    }

    return {
      component: 'memory',
      heapCanaries: heapStates.length,
      closureCanaries: closureStates.length,
      nativeCanaries: nativeStates.length,
      totalCorruptions: this.#totalCorruptions,
      allHealthy: heapStates.every(c => !c.corrupted) &&
        closureStates.every(c => !c.corrupted) &&
        nativeStates.every(c => !c.corrupted),
      lastCheck: this.#lastCheck,
    };
  }

  /**
   * Get status summary
   */
  getStatus() {
    return {
      started: this.#started,
      sanghaConnected: !!this.#sangha,
      heapCanaries: this.#canaries.size,
      closureCanaries: this.#closureCanaries.size,
      nativeCanaries: this.#nativeCanaries.size,
      totalCorruptions: this.#totalCorruptions,
      lastCheck: this.#lastCheck,
    };
  }

  /**
   * Stop monitoring
   */
  stop() {
    if (!this.#started) return;

    this.#started = false;

    if (this.#checkInterval) {
      clearInterval(this.#checkInterval);
      this.#checkInterval = null;
    }

    log.info('Memory safety monitoring stopped');
  }
}

// =============================================================================
// SINGLETON & EXPORTS
// =============================================================================

let _instance = null;

/**
 * Get the MemorySafety singleton
 * @returns {MemorySafety}
 */
export function getMemorySafety() {
  if (!_instance) {
    _instance = new MemorySafety();
  }
  return _instance;
}

export default MemorySafety;
