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
 * STEADYWATCH — Quantum-Hardware-Validated Entropy Seed Module
 * 
 * Loads Hurwitz quaternion satellite seeds (256-bit each) generated on
 * IBM ibm_marrakesh (156-qubit Heron r2) via STEADYWATCH circuits.
 * 
 * Math:  Satellites = 24 * (p + 1)  for prime p
 *   p=5  -> 144 nodes
 *   p=13 -> 336 nodes  
 *   p=17 -> 432 nodes
 * 
 * Integration: XOR quantum seed with local CSPRNG output to create
 * hybrid entropy for ML-KEM-768 keygen. Two-source extractor pattern
 * ensures keys remain secure even if one entropy source is compromised.
 * 
 * @module security/steadywatch
 * @license MIT
 * @copyright 2026 YAKMESH Contributors
 */

import { randomBytes } from 'crypto';
import { readFileSync, existsSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createLogger } from '../utils/logger.js';
import { sha3_256, sha3_256hex } from '../utils/accel.js';

// ═══ TRIBHUJ — Balanced ternary quality verdicts ═══
import { Trit, TritArray, POSITIVE, NEUTRAL, NEGATIVE, TritState } from '../oracle/tribhuj.js';

// ═══ SST — Synergy Sequence Theory for family grouping & Fibonacci rotation ═══
import {
  digitalRoot, getFamily, getFamilyOf, toFamilyTrit,
  fibonacciRoot, fibonacciFamily, fibonacciFamilyTrit,
  SSTFamily, FAMILY_TO_TRIT, FIBONACCI_CYCLE_24,
} from '../oracle/sst.js';

const log = createLogger('security:steadywatch');

// ===================================================================
// CONSTANTS
// ===================================================================

/** Hurwitz quaternion satellite count per prime */
const SATELLITE_COUNTS = Object.freeze({
  5:  144,   // 24 * (5 + 1)  — validated Feb 1 2026
  13: 336,   // 24 * (13 + 1) — future batch
  17: 432,   // 24 * (17 + 1) — future batch
});

/** Expected seed size in bytes */
const SEED_BYTES = 32;       // 256-bit per satellite seed
/** Required output for ML-KEM-768 keygen */
const KEYGEN_SEED_BYTES = 64;
/** Minimum acceptable min-entropy ratio (bits of entropy / total bits) */
const MIN_ENTROPY_RATIO = 0.75;

// ═══ TERNARY-144 CONSTANTS ═══

/** 
 * 6-trit address space for satellite indexing.
 * 144 in balanced ternary = "1TT100" (6 trits).
 * 3^5 = 243 > 144, so 5 trits suffice, but 6 trits are used for
 * balanced addressing that encodes the satellite's numeric position.
 */
const TRIT_ADDRESS_LENGTH = 6;

/**
 * SST family distribution for 144 satellites.
 * Indices are classified by their digital root's SST family:
 *   Family A (1,4,7): ~48 satellites — Physical Negative (descending)
 *   Family B (2,5,8): ~48 satellites — Physical Positive (ascending)
 *   Family C (3,6,9): ~48 satellites — Governing Source (singularity)
 * 
 * DR(144) = 9 → Family C → The 144 constellation itself is a NEUTRAL singularity.
 */
const FAMILY_GROUPS = Object.freeze({
  [SSTFamily.A]: [], // Populated at load time
  [SSTFamily.B]: [],
  [SSTFamily.C]: [],
});

// ===================================================================
// TELEMETRY
// ===================================================================

const telemetry = {
  seedsLoaded: 0,
  hybridSeeds: 0,
  rotations: 0,
  biasRejections: 0,
  sentinelChecks: 0,
  sentinelPasses: 0,
  sentinelFails: 0,
  lastSeedIndex: -1,
  // Ternary-144 telemetry
  familySelections: { A: 0, B: 0, C: 0 },
  fibonacciCyclePosition: 0,
  ternaryQualityVerdicts: { positive: 0, neutral: 0, negative: 0 },
  tritAddressLookups: 0,
  batchConsensusRuns: 0,
};

// ===================================================================
// SEED STORE
// ===================================================================

/**
 * STEADYWATCH Seed Store.
 * Manages the 144+ satellite seeds and provides hybrid entropy generation.
 */
class SteadywatchSeedStore {
  constructor() {
    /** @type {Uint8Array[]} Array of 256-bit satellite seeds */
    this.seeds = [];
    /** Current rotation index */
    this.rotationIndex = 0;
    /** Source prime used to generate this seed set */
    this.prime = 0;
    /** IBM Quantum job metadata */
    this.metadata = null;
    /** Whether seeds are loaded and validated */
    this.initialized = false;
    /** Node-specific seed assignment (index into seeds array) */
    this.nodeAssignment = -1;
    /** Entropy quality scores per seed (from Sentinel) */
    this.qualityScores = new Map();

    // ═══ TERNARY-144 STATE ═══

    /** 
     * SST family groups — indices organized by digital root family.
     * @type {{ A: number[], B: number[], C: number[] }} 
     */
    this.familyGroups = { A: [], B: [], C: [] };

    /** 
     * 6-trit balanced ternary address for each satellite.
     * @type {Map<number, TritArray>} index → TritArray("1TT100"-range) 
     */
    this.tritAddresses = new Map();

    /** 
     * Reverse lookup: trit string → seed index.
     * @type {Map<string, number>} 
     */
    this.tritIndex = new Map();

    /**
     * Ternary quality verdicts per seed.
     * POSITIVE = excellent entropy, NEUTRAL = acceptable, NEGATIVE = biased/rejected.
     * @type {Map<number, Trit>}
     */
    this.qualityVerdicts = new Map();

    /**
     * Fibonacci cycle position for rotation.
     * Advances through the 24-position cycle, selecting seeds family-aware.
     */
    this.fibCyclePos = 0;
  }

  /**
   * Load seeds from a JSON file.
   * Expected format:
   * {
   *   "prime": 5,
   *   "satelliteCount": 144,
   *   "backend": "ibm_marrakesh",
   *   "validated": "2026-02-01",
   *   "seeds": ["hex-encoded-32-bytes", ...]
   * }
   * 
   * @param {string} seedFilePath — path to seeds JSON
   * @returns {boolean} — true if loaded and validated
   */
  load(seedFilePath) {
    try {
      if (!existsSync(seedFilePath)) {
        log.warn('STEADYWATCH seed file not found:', seedFilePath);
        return false;
      }

      const raw = readFileSync(seedFilePath, 'utf-8');
      const data = JSON.parse(raw);

      // Validate structure
      if (!data.seeds || !Array.isArray(data.seeds)) {
        log.error('Invalid seed file: missing seeds array');
        return false;
      }

      this.prime = data.prime || 5;
      const expectedCount = SATELLITE_COUNTS[this.prime];
      if (expectedCount && data.seeds.length !== expectedCount) {
        log.warn('Seed count mismatch: expected ' + expectedCount + ' for p=' + this.prime + ', got ' + data.seeds.length);
      }

      // Parse and validate each seed
      this.seeds = [];
      const fingerprints = new Set();

      for (let i = 0; i < data.seeds.length; i++) {
        const hex = data.seeds[i];
        if (hex.length !== SEED_BYTES * 2) {
          log.warn('Seed ' + i + ': invalid length ' + hex.length + ', expected ' + (SEED_BYTES * 2));
          continue;
        }

        const seedBytes = hexToUint8(hex);
        
        // Check uniqueness via SHA3 fingerprint
        const fp = sha3_256hex(seedBytes);
        if (fingerprints.has(fp)) {
          log.warn('Seed ' + i + ': duplicate detected (fingerprint collision)');
          telemetry.biasRejections++;
          continue;
        }
        fingerprints.add(fp);

        // Bias check: ensure reasonable byte distribution
        if (!this._checkBias(seedBytes, i)) {
          telemetry.biasRejections++;
          continue;
        }

        this.seeds.push(seedBytes);
      }

      this.metadata = {
        prime: this.prime,
        backend: data.backend || 'unknown',
        validated: data.validated || 'unknown',
        jobIds: data.jobIds || [],
        loadedAt: new Date().toISOString(),
        seedCount: this.seeds.length,
      };

      telemetry.seedsLoaded = this.seeds.length;
      this.initialized = this.seeds.length > 0;

      // ═══ Build ternary-144 structures ═══
      if (this.initialized) {
        this._buildTernaryStructures();
      }

      log.info('STEADYWATCH loaded: ' + this.seeds.length + ' satellite seeds (p=' + this.prime + ', backend=' + this.metadata.backend + ')');
      return this.initialized;

    } catch (err) {
      log.error('Failed to load STEADYWATCH seeds:', err.message);
      return false;
    }
  }

  /**
   * Generate initial seeds from quantum circuit parameters.
   * Used when no seed file exists — creates deterministic seeds from
   * Hurwitz quaternion phase rotations.
   * 
   * theta_i = 2*pi*i / N  where N = 24(p+1)
   * seed_i = SHA3-256(quaternion_coordinate || circuit_measurement)
   * 
   * NOTE: This is a simulation. Real seeds come from IBM Quantum hardware.
   * Use this only for development/testing.
   * 
   * @param {number} prime — Hurwitz prime (5, 13, or 17)
   * @param {string} [outputPath] — save generated seeds to file
   * @returns {boolean}
   */
  generateTestSeeds(prime = 5, outputPath = null) {
    const count = SATELLITE_COUNTS[prime];
    if (!count) {
      log.error('Invalid prime ' + prime + '. Use 5, 13, or 17.');
      return false;
    }

    log.info('Generating ' + count + ' test seeds for p=' + prime + ' (SIMULATION)');

    const seeds = [];
    for (let i = 0; i < count; i++) {
      // Hurwitz quaternion phase rotation
      const theta = (2 * Math.PI * i) / count;
      
      // Simulate quaternion coordinate: q = cos(theta) + sin(theta)*i + ...
      // In real STEADYWATCH, this parameterizes an 8-qubit circuit
      const qReal = Math.cos(theta);
      const qImag = Math.sin(theta);
      
      // Create deterministic but unique input for SHA3
      const input = Buffer.alloc(48);
      input.writeDoubleBE(qReal, 0);
      input.writeDoubleBE(qImag, 8);
      input.writeUInt32BE(prime, 16);
      input.writeUInt32BE(i, 20);
      input.writeDoubleBE(theta, 24);
      // Add satellite-specific label
      const label = 'STEADYWATCH-SAT-' + prime + '-' + i;
      Buffer.from(label).copy(input, 32);

      // SHA3-256 of quaternion parameters -> 256-bit seed
      const seed = sha3_256(input);
      seeds.push(Buffer.from(seed).toString('hex'));
    }

    const data = {
      prime,
      satelliteCount: count,
      backend: 'simulation',
      validated: new Date().toISOString().split('T')[0],
      note: 'TEST SEEDS — generated from Hurwitz quaternion simulation, not IBM Quantum hardware',
      seeds,
    };

    if (outputPath) {
      writeFileSync(outputPath, JSON.stringify(data, null, 2));
      log.info('Test seeds written to ' + outputPath);
    }

    // Load seeds in-memory
    this.seeds = seeds.map(h => hexToUint8(h));
    this.prime = prime;
    this.metadata = {
      prime,
      backend: 'simulation',
      validated: data.validated,
      seedCount: count,
      loadedAt: new Date().toISOString(),
    };
    this.initialized = true;
    telemetry.seedsLoaded = count;

    // Build ternary-144 structures (family groups, trit addresses)
    if (this.initialized) {
      this._buildTernaryStructures();
    }

    return true;
  }

  /**
   * Assign this node a specific satellite seed index.
   * In production: provisioned by DOKO identity ceremony.
   * 
   * @param {number} index — satellite index [0, seedCount)
   */
  assignNode(index) {
    if (index < 0 || index >= this.seeds.length) {
      log.error('Invalid node assignment: ' + index + ' (have ' + this.seeds.length + ' seeds)');
      return;
    }
    this.nodeAssignment = index;
    this.rotationIndex = index;
    log.info('Node assigned to satellite ' + index + ' (seed fingerprint: ' + sha3_256hex(this.seeds[index]).slice(0, 16) + '...)');
  }

  /**
   * Get a hybrid seed suitable for ML-KEM-768 keygen.
   * 
   * Algorithm:
   *   1. Select satellite seed (rotation or assigned)
   *   2. Generate 64 bytes from OS CSPRNG
   *   3. Expand satellite seed to 64 bytes: SHA3-256(seed || "EXPAND-0") || SHA3-256(seed || "EXPAND-1")
   *   4. XOR: hybridSeed = expandedSatellite XOR csprng
   *   5. Return 64-byte hybrid seed for ml_kem768.keygen()
   * 
   * Security property: Even if one source is fully compromised (weak VM CSPRNG
   * or faulty quantum hardware), the other source ensures the hybrid seed
   * retains at least 256 bits of entropy.
   * 
   * @returns {Uint8Array} — 64-byte hybrid seed
   */
  /**
   * Get a hybrid seed suitable for ML-KEM-768 keygen.
   * 
   * Algorithm (Ternary-144 enhanced):
   *   1. Advance Fibonacci 24-cycle position
   *   2. Determine SST family for this position
   *   3. Select satellite from matching family group (family-aware rotation)
   *   4. Generate 64 bytes from OS CSPRNG
   *   5. Expand satellite seed to 64 bytes: SHA3-256(seed || "EXPAND-0") || SHA3-256(seed || "EXPAND-1")
   *   6. XOR: hybridSeed = expandedSatellite XOR csprng
   *   7. Return 64-byte hybrid seed for ml_kem768.keygen()
   * 
   * @returns {Uint8Array} — 64-byte hybrid seed
   */
  getHybridSeed() {
    if (!this.initialized || this.seeds.length === 0) {
      log.trace('STEADYWATCH not initialized, falling back to pure CSPRNG');
      return randomBytes(KEYGEN_SEED_BYTES);
    }

    // ═══ TERNARY-144: Fibonacci-cycle family-aware seed selection ═══
    let seedIndex;

    if (this.nodeAssignment >= 0) {
      // Node has a fixed assignment — use it, but still track Fibonacci position
      seedIndex = this.nodeAssignment;
    } else if (this.familyGroups.A.length > 0) {
      // Use Fibonacci 24-cycle to pick the SST family, then round-robin within family
      const fibRoot = fibonacciRoot(this.fibCyclePos);
      const family = getFamily(fibRoot);
      const familyGroup = this.familyGroups[family];

      if (familyGroup.length > 0) {
        // Round-robin within the selected family
        const familyOffset = this.rotationIndex % familyGroup.length;
        seedIndex = familyGroup[familyOffset];
        telemetry.familySelections[family]++;
      } else {
        // Fallback: linear rotation if family group is empty
        seedIndex = this.rotationIndex;
      }

      this.fibCyclePos = (this.fibCyclePos + 1) % 24;
      telemetry.fibonacciCyclePosition = this.fibCyclePos;
    } else {
      // Fallback: simple linear rotation (pre-ternary behavior)
      seedIndex = this.rotationIndex;
    }
    
    const satelliteSeed = this.seeds[seedIndex % this.seeds.length];

    // Rotate for next call (even if assigned, rotate for re-key diversity)
    this.rotationIndex = (this.rotationIndex + 1) % this.seeds.length;
    telemetry.rotations++;

    // Expand 32-byte satellite seed to 64 bytes using SHA3 (ACCEL: native SHA-NI)
    const expand0 = sha3_256(Buffer.concat([
      Buffer.from(satelliteSeed),
      Buffer.from('EXPAND-0'),
    ]));
    const expand1 = sha3_256(Buffer.concat([
      Buffer.from(satelliteSeed),
      Buffer.from('EXPAND-1'),
    ]));
    const expandedSeed = new Uint8Array(KEYGEN_SEED_BYTES);
    expandedSeed.set(expand0, 0);
    expandedSeed.set(expand1, 32);

    // CSPRNG contribution
    const csprng = randomBytes(KEYGEN_SEED_BYTES);

    // XOR: two-source extractor
    const hybridSeed = new Uint8Array(KEYGEN_SEED_BYTES);
    for (let i = 0; i < KEYGEN_SEED_BYTES; i++) {
      hybridSeed[i] = expandedSeed[i] ^ csprng[i];
    }

    telemetry.hybridSeeds++;
    telemetry.lastSeedIndex = seedIndex;

    log.trace('Hybrid seed generated (satellite ' + seedIndex + 
              ', family ' + getFamilyOf(seedIndex) + 
              ', fibPos ' + this.fibCyclePos + 
              ', rotation ' + this.rotationIndex + ')');
    return hybridSeed;
  }

  /**
   * ═══ TERNARY SEED QUALITY ═══
   * 
   * Evaluate a seed's entropy quality as a balanced ternary verdict.
   * Replaces the old boolean _checkBias with three-valued logic:
   *   POSITIVE (+1): Excellent entropy — diverse bytes, no bias patterns
   *   NEUTRAL  ( 0): Acceptable entropy — passes minimum thresholds
   *   NEGATIVE (-1): Biased/rejected — fails quality checks
   * 
   * @param {Uint8Array} seedBytes — 256-bit seed
   * @param {number} index — satellite index
   * @returns {Trit} — ternary quality verdict
   */
  _checkBiasTernary(seedBytes, index) {
    let zeros = 0;
    let ones = 0;
    const byteSet = new Set();

    for (const b of seedBytes) {
      if (b === 0x00) zeros++;
      if (b === 0xFF) ones++;
      byteSet.add(b);
    }

    // NEGATIVE: Hard reject — severe bias
    if (zeros > SEED_BYTES * 0.5) {
      log.warn('Seed ' + index + ': NEGATIVE — excessive zero bytes (' + zeros + '/' + SEED_BYTES + ')');
      telemetry.ternaryQualityVerdicts.negative++;
      return new Trit(NEGATIVE);
    }
    if (ones > SEED_BYTES * 0.5) {
      log.warn('Seed ' + index + ': NEGATIVE — excessive 0xFF bytes (' + ones + '/' + SEED_BYTES + ')');
      telemetry.ternaryQualityVerdicts.negative++;
      return new Trit(NEGATIVE);
    }
    if (byteSet.size < SEED_BYTES * 0.25) {
      log.warn('Seed ' + index + ': NEGATIVE — low byte diversity (' + byteSet.size + ' unique)');
      telemetry.ternaryQualityVerdicts.negative++;
      return new Trit(NEGATIVE);
    }

    // POSITIVE: Excellent — high diversity, balanced distribution
    if (byteSet.size >= SEED_BYTES * 0.75 && zeros <= 2 && ones <= 2) {
      telemetry.ternaryQualityVerdicts.positive++;
      return new Trit(POSITIVE);
    }

    // NEUTRAL: Acceptable but not exceptional
    telemetry.ternaryQualityVerdicts.neutral++;
    return new Trit(NEUTRAL);
  }

  /**
   * Backward-compatible wrapper — _checkBias still returns boolean for load().
   * Internally uses ternary verdict.
   * @private
   */
  _checkBias(seedBytes, index) {
    const verdict = this._checkBiasTernary(seedBytes, index);
    this.qualityVerdicts.set(index, verdict);
    return !verdict.isNegative; // POSITIVE and NEUTRAL both pass
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TERNARY-144: SST FAMILY SATELLITE GROUPING
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Classify all loaded satellite seeds into SST family groups.
   * 
   * Each satellite index i is assigned to a family based on digitalRoot(i+1):
   *   Family A (DR 1,4,7) ← Physical Negative
   *   Family B (DR 2,5,8) ← Physical Positive
   *   Family C (DR 3,6,9) ← Governing Source
   * 
   * For 144 satellites: each family gets exactly 48 members (perfectly balanced).
   * This reflects 144's digital root (9) — a governing singularity that divides
   * evenly across all three polarities.
   */
  _buildFamilyGroups() {
    this.familyGroups = { A: [], B: [], C: [] };

    for (let i = 0; i < this.seeds.length; i++) {
      // Use i+1 so satellite 0 → DR(1) = Family A, satellite 1 → DR(2) = Family B, etc.
      const family = getFamilyOf(i + 1);
      this.familyGroups[family].push(i);
    }

    log.info('SST family groups: A=' + this.familyGroups.A.length + 
             ' B=' + this.familyGroups.B.length + 
             ' C=' + this.familyGroups.C.length);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TERNARY-144: 6-TRIT SATELLITE ADDRESSES
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Assign each satellite a 6-trit balanced ternary address.
   * 
   * 144 in balanced ternary = "1TT100" (6 trits):
   *   1×243 + (-1)×81 + (-1)×27 + 1×9 + 0×3 + 0×1 = 243 - 81 - 27 + 9 = 144
   * 
   * Each satellite gets its index converted to a fixed-width 6-trit address.
   * This enables ternary trie routing for seed lookups instead of array indexing.
   * 
   * Satellite 0  → "000000"  (0)
   * Satellite 1  → "00000+1" ("000001")
   * Satellite 72 → "10T100"  (midpoint)
   * Satellite 143 → just below "1TT100"
   */
  _buildTritAddresses() {
    this.tritAddresses.clear();
    this.tritIndex.clear();

    for (let i = 0; i < this.seeds.length; i++) {
      const addr = TritArray.fromDecimal(i, TRIT_ADDRESS_LENGTH);
      this.tritAddresses.set(i, addr);
      this.tritIndex.set(addr.toString(), i);
    }

    log.info('Trit addresses assigned: ' + this.tritAddresses.size + 
             ' satellites in 6-trit space (capacity: 3^5=' + Math.pow(3, 5) + ')');
  }

  /**
   * Look up a satellite seed by its 6-trit address.
   * 
   * @param {TritArray | string} address — 6-trit balanced ternary address
   * @returns {Uint8Array | null} — seed bytes, or null if not found
   */
  getSeedByTritAddress(address) {
    telemetry.tritAddressLookups++;
    const key = address instanceof TritArray ? address.toString() : address;
    const index = this.tritIndex.get(key);
    if (index === undefined) return null;
    return { index, seed: this.seeds[index] ?? null };
  }

  /**
   * Get the 6-trit address for a satellite index.
   * @param {number} index
   * @returns {TritArray | null}
   */
  getTritAddress(index) {
    return this.tritAddresses.get(index) ?? null;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TERNARY-144: BATCH SEED CONSENSUS
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Validate a batch of seed quality verdicts using TritArray consensus.
   * 
   * After loading, each seed has a ternary quality verdict (from _checkBiasTernary).
   * This method aggregates them using TritArray.majority() to determine the
   * overall quality of the seed batch.
   * 
   * A batch with POSITIVE majority indicates high-quality quantum entropy.
   * A batch with NEUTRAL majority suggests mixed quality (acceptable).
   * A batch with NEGATIVE majority triggers a warning — seeds may be compromised.
   * 
   * @returns {{ majority: Trit, counts: Object, balanced: boolean }}
   */
  batchQualityConsensus() {
    telemetry.batchConsensusRuns++;

    const verdicts = [];
    for (let i = 0; i < this.seeds.length; i++) {
      const v = this.qualityVerdicts.get(i);
      verdicts.push(v ? v.value : NEUTRAL);
    }

    if (verdicts.length === 0) {
      return { majority: new Trit(NEUTRAL), counts: { negative: 0, neutral: 0, positive: 0 }, total: 0, balanced: true };
    }

    const tritArr = new TritArray(verdicts);
    const majority = tritArr.majority();
    const counts = tritArr.count();
    const balanced = tritArr.isBalanced();

    if (majority.isNegative) {
      log.warn('STEADYWATCH batch consensus: NEGATIVE — seed quality may be compromised');
    } else if (majority.isPositive) {
      log.info('STEADYWATCH batch consensus: POSITIVE — excellent seed quality');
    }

    return { majority, counts, total: verdicts.length, balanced };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TERNARY-144: FAMILY-AWARE SEED SELECTION
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Select a seed from a specific SST family.
   * 
   * @param {string} family — 'A', 'B', or 'C'
   * @param {number} [offset=0] — offset within the family group
   * @returns {{ index: number, seed: Uint8Array, address: TritArray, quality: Trit } | null}
   */
  selectFromFamily(family, offset = 0) {
    const group = this.familyGroups[family];
    if (!group || group.length === 0) return null;

    const index = group[offset % group.length];
    return {
      index,
      seed: this.seeds[index],
      family,
      address: this.tritAddresses.get(index) || null,
      quality: this.qualityVerdicts.get(index) || new Trit(NEUTRAL),
    };
  }

  /**
   * Select a seed using the Fibonacci 24-cycle family mapping.
   * Each call advances the cycle position and picks from the indicated family.
   * 
   * The SST family at Fibonacci position n determines which pool to draw from:
   *   fibRoot(0) = 1 → Family A → pick from NEGATIVE polarity satellites
   *   fibRoot(1) = 1 → Family A → same
   *   fibRoot(2) = 2 → Family B → pick from POSITIVE polarity satellites
   *   fibRoot(3) = 3 → Family C → pick from GOVERNING satellites
   *   ...repeats every 24 positions (the Fibonacci digital root cycle)
   * 
   * At cycle positions 12 and 24: fibRoot = 9 → Family C → singularity marker
   * 
   * @returns {{ index: number, seed: Uint8Array, family: string, fibPosition: number, fibRoot: number }}
   */
  selectByFibonacciCycle() {
    const pos = this.fibCyclePos;
    const root = fibonacciRoot(pos);
    const family = getFamily(root);
    const familyTrit = toFamilyTrit(root);

    const group = this.familyGroups[family];
    if (!group || group.length === 0) {
      // Fallback to linear
      return {
        index: this.rotationIndex % this.seeds.length,
        seed: this.seeds[this.rotationIndex % this.seeds.length],
        family,
        fibPosition: pos,
        fibRoot: root,
      };
    }

    // Use rotation index modulo family group size
    const familyOffset = this.rotationIndex % group.length;
    const index = group[familyOffset];

    // Advance cycle
    this.fibCyclePos = (this.fibCyclePos + 1) % 24;
    telemetry.familySelections[family]++;
    telemetry.fibonacciCyclePosition = this.fibCyclePos;

    return {
      index,
      seed: this.seeds[index],
      family,
      fibPosition: pos,
      fibRoot: root,
      familyTrit: familyTrit.value,
      address: this.tritAddresses.get(index)?.toString() || null,
    };
  }

  /**
   * Build all ternary-144 structures after seeds are loaded.
   * Called automatically at end of load() and generateTestSeeds().
   * @private
   */
  _buildTernaryStructures() {
    this._buildFamilyGroups();
    this._buildTritAddresses();

    // Log the mathematical harmony
    const totalDR = digitalRoot(this.seeds.length);
    const totalFamily = getFamily(totalDR);
    const totalTrit = toFamilyTrit(this.seeds.length);
    
    log.info('Ternary-144: DR(' + this.seeds.length + ')=' + totalDR + 
             ' → Family ' + totalFamily + 
             ' → TRIT ' + totalTrit.toChar() +
             ' | constellation address: ' + TritArray.fromDecimal(this.seeds.length, TRIT_ADDRESS_LENGTH).toString());
  }

  /**
   * Get status report
   */
  getStatus() {
    // Quality consensus (if seeds loaded)
    let consensus = null;
    if (this.qualityVerdicts.size > 0) {
      consensus = this.batchQualityConsensus();
      consensus.majority = consensus.majority.toChar(); // serializable
    }

    return {
      initialized: this.initialized,
      prime: this.prime,
      seedCount: this.seeds.length,
      nodeAssignment: this.nodeAssignment,
      rotationIndex: this.rotationIndex,
      metadata: this.metadata,
      telemetry: { ...telemetry },
      // Ternary-144 status
      ternary: {
        familyGroups: {
          A: this.familyGroups.A.length,
          B: this.familyGroups.B.length,
          C: this.familyGroups.C.length,
        },
        fibCyclePos: this.fibCyclePos,
        tritAddressCount: this.tritAddresses.size,
        constellationDR: this.seeds.length > 0 ? digitalRoot(this.seeds.length) : 0,
        constellationFamily: this.seeds.length > 0 ? getFamily(digitalRoot(this.seeds.length)) : null,
        constellationAddress: this.seeds.length > 0 
          ? TritArray.fromDecimal(this.seeds.length, TRIT_ADDRESS_LENGTH).toString() 
          : null,
        consensus,
      },
    };
  }
}

// ===================================================================
// ENTROPY SENTINEL — NPU-Accelerated Quality Monitor
// ===================================================================

/**
 * Entropy Sentinel uses the ACCEL InferenceEngine (NPU/GPU/CPU) to
 * score the quality of seed material before it enters keygen.
 * 
 * Novel use: the AMD NPU or NVIDIA GPU runs a small ONNX model that
 * detects patterns in byte sequences that indicate weak randomness:
 * - Low bit-entropy (information density per byte)
 * - Repeating patterns (autocorrelation)
 * - Byte frequency bias
 * - Sequential runs
 * 
 * If no ONNX model is loaded, falls back to software statistical tests.
 */
class EntropySentinel {
  constructor() {
    this._inferenceEngine = null;
    this._modelLoaded = false;
    this._modelName = 'entropy-sentinel';
  }

  /**
   * Initialize with ACCEL inference engine reference.
   * @param {import('../utils/accel.js').InferenceEngine} engine
   */
  async initialize(engine) {
    this._inferenceEngine = engine;
    
    if (engine && engine.hasModel(this._modelName)) {
      this._modelLoaded = true;
      log.info('Entropy Sentinel: NPU/GPU model loaded');
    } else {
      log.debug('Entropy Sentinel: using software statistical tests (no ONNX model)');
    }
  }

  /**
   * Convert a numeric score to a TRIBHUJ ternary verdict.
   * ≥ 0.85 → POSITIVE (excellent entropy)
   * ≥ 0.50 → NEUTRAL  (acceptable entropy)
   * <  0.50 → NEGATIVE (poor entropy — reject)
   *
   * @param {number} score — 0.0 to 1.0
   * @returns {import('../../oracle/tribhuj.js').Trit}
   */
  _scoreToVerdict(score) {
    if (score >= 0.85) return new Trit(POSITIVE);
    if (score >= 0.50) return new Trit(NEUTRAL);
    return new Trit(NEGATIVE);
  }

  /**
   * Score entropy quality of a byte sequence.
   * Returns a score from 0.0 (terrible) to 1.0 (excellent),
   * plus a TRIBHUJ ternary verdict (POSITIVE/NEUTRAL/NEGATIVE).
   * 
   * NPU path: runs ONNX model for pattern detection
   * CPU path: bit-entropy + byte frequency chi-square
   * 
   * @param {Uint8Array} data — seed or key material
   * @returns {Promise<{ score: number, verdict: Trit, method: 'npu'|'gpu'|'cpu', details: Object }>}
   */
  async score(data) {
    telemetry.sentinelChecks++;

    // Try NPU/GPU inference first
    if (this._modelLoaded && this._inferenceEngine) {
      try {
        // Model expects exactly 32 features — bin input bytes into 32 segments
        const MODEL_INPUTS = 32;
        const inputTensor = new Float32Array(MODEL_INPUTS);
        if (data.length <= MODEL_INPUTS) {
          // Short input: use directly, pad remainder with 0
          for (let i = 0; i < data.length; i++) inputTensor[i] = data[i] / 255.0;
        } else {
          // Longer input: average each bin for representative features
          const binSize = data.length / MODEL_INPUTS;
          for (let b = 0; b < MODEL_INPUTS; b++) {
            const start = Math.floor(b * binSize);
            const end = Math.floor((b + 1) * binSize);
            let sum = 0;
            for (let i = start; i < end; i++) sum += data[i];
            inputTensor[b] = (sum / (end - start)) / 255.0;
          }
        }

        const result = await this._inferenceEngine.infer(this._modelName, {
          seed_bytes: inputTensor,
        });

        if (result && result.quality_score) {
          const score = result.quality_score[0];
          telemetry.sentinelPasses += score >= MIN_ENTROPY_RATIO ? 1 : 0;
          telemetry.sentinelFails += score < MIN_ENTROPY_RATIO ? 1 : 0;
          
          const provider = this._inferenceEngine.provider || '';
          return {
            score,
            verdict: this._scoreToVerdict(score),
            method: provider.includes('Dml') ? 'npu' 
                  : provider.includes('CUDA') ? 'gpu' : 'cpu',
            details: { raw: result },
          };
        }
      } catch (err) {
        log.trace('Sentinel NPU inference failed, falling back to software:', err.message);
      }
    }

    // Software fallback: bit-entropy + chi-square
    return this._softwareScore(data);
  }

  /**
   * Software statistical scoring (no NPU required).
   * @private
   */
  _softwareScore(data) {
    const len = data.length;
    if (len === 0) return { score: 0, verdict: new Trit(NEGATIVE), method: 'cpu', details: {} };

    // 1. Bit-entropy (information density per byte, max 8.0 bits)
    const freq = new Uint32Array(256);
    for (const b of data) freq[b]++;
    
    let bitEntropy = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] === 0) continue;
      const p = freq[i] / len;
      bitEntropy -= p * Math.log2(p);
    }
    const entropyNorm = bitEntropy / 8.0; // Normalized to [0, 1]

    // 2. Chi-square test for uniform distribution
    const expected = len / 256;
    let chiSquare = 0;
    for (let i = 0; i < 256; i++) {
      const diff = freq[i] - expected;
      chiSquare += (diff * diff) / expected;
    }
    // Normalize: chi-square for 255 DOF, p=0.05 critical ~ 293.25
    const chiNorm = Math.max(0, 1 - chiSquare / 600);

    // 3. Run length test (consecutive identical bytes)
    let maxRun = 0;
    let currentRun = 1;
    for (let i = 1; i < len; i++) {
      if (data[i] === data[i - 1]) {
        currentRun++;
        if (currentRun > maxRun) maxRun = currentRun;
      } else {
        currentRun = 1;
      }
    }
    const runNorm = Math.max(0, 1 - maxRun / 8);

    // 4. Autocorrelation at lag 1
    let mean = 0;
    for (const b of data) mean += b;
    mean /= len;
    let num = 0, den = 0;
    for (let i = 0; i < len - 1; i++) {
      num += (data[i] - mean) * (data[i + 1] - mean);
      den += (data[i] - mean) ** 2;
    }
    const autocorr = den === 0 ? 0 : Math.abs(num / den);
    const autoNorm = Math.max(0, 1 - autocorr * 5);

    // Combined score (weighted)
    const score = entropyNorm * 0.4 + chiNorm * 0.25 + runNorm * 0.15 + autoNorm * 0.2;

    telemetry.sentinelPasses += score >= MIN_ENTROPY_RATIO ? 1 : 0;
    telemetry.sentinelFails += score < MIN_ENTROPY_RATIO ? 1 : 0;

    return {
      score: Math.round(score * 1000) / 1000,
      verdict: this._scoreToVerdict(score),
      method: 'cpu',
      details: {
        bitEntropyPerByte: Math.round(bitEntropy * 1000) / 1000,
        entropyNorm: Math.round(entropyNorm * 1000) / 1000,
        chiSquare: Math.round(chiSquare * 10) / 10,
        chiNorm: Math.round(chiNorm * 1000) / 1000,
        maxRunLength: maxRun,
        runNorm: Math.round(runNorm * 1000) / 1000,
        autocorrelation: Math.round(autocorr * 1000) / 1000,
        autoNorm: Math.round(autoNorm * 1000) / 1000,
      },
    };
  }
}

// ===================================================================
// UTILITIES
// ===================================================================

function hexToUint8(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// ===================================================================
// SINGLETONS & EXPORTS
// ===================================================================

/** Global STEADYWATCH seed store */
export const seedStore = new SteadywatchSeedStore();

/** Global Entropy Sentinel */
export const sentinel = new EntropySentinel();

/**
 * Initialize STEADYWATCH subsystem.
 * 
 * @param {Object} options
 * @param {string} [options.seedFile] — path to satellite seeds JSON
 * @param {number} [options.nodeIndex] — assigned satellite index for this node
 * @param {number} [options.prime=5] — Hurwitz prime for test seed generation
 * @param {boolean} [options.generateTest=false] — generate test seeds if no file
 * @param {import('../utils/accel.js').InferenceEngine} [options.inferenceEngine] — ACCEL inference engine
 * @returns {Promise<{ initialized: boolean, seedCount: number, sentinel: boolean }>}
 */
export async function initialize(options = {}) {
  const {
    seedFile,
    nodeIndex,
    prime = 5,
    generateTest = false,
    inferenceEngine = null,
  } = options;

  // Load seeds
  let loaded = false;
  if (seedFile) {
    loaded = seedStore.load(seedFile);
  }
  
  if (!loaded && generateTest) {
    const defaultPath = join(
      dirname(fileURLToPath(import.meta.url)),
      '../data/steadywatch-seeds-p' + prime + '.json'
    );
    seedStore.generateTestSeeds(prime, defaultPath);
    loaded = seedStore.initialized;
  }

  // Assign node
  if (loaded && typeof nodeIndex === 'number') {
    seedStore.assignNode(nodeIndex);
  }

  // Initialize Sentinel
  if (inferenceEngine) {
    await sentinel.initialize(inferenceEngine);
  }

  const status = {
    initialized: seedStore.initialized,
    seedCount: seedStore.seeds.length,
    sentinel: sentinel._modelLoaded,
  };

  log.info('STEADYWATCH initialized:', status);
  return status;
}

/**
 * Get a hybrid quantum+CSPRNG seed for ML-KEM-768 keygen.
 * This is the primary integration point for ANNEX.
 * 
 * @returns {Uint8Array} — 64-byte seed
 */
export function getHybridSeed() {
  return seedStore.getHybridSeed();
}

/**
 * Score entropy quality of arbitrary byte data.
 * Uses NPU/GPU if available, software fallback otherwise.
 * Returns numeric score + TRIBHUJ ternary verdict.
 * 
 * @param {Uint8Array} data
 * @returns {Promise<{ score: number, verdict: Trit, method: string, details: Object }>}
 */
export async function scoreEntropy(data) {
  return sentinel.score(data);
}

/**
 * Select a seed using Fibonacci-cycle family-aware rotation.
 * Advances the 24-position Fibonacci cycle, determines the SST
 * family for the current position, and selects from matching satellites.
 * 
 * @returns {{ seed: Uint8Array, index: number, family: string, fibPos: number, address: TritArray|null }}
 */
export function selectByFibonacciCycle() {
  return seedStore.selectByFibonacciCycle();
}

/**
 * Get seed by 6-trit balanced ternary address.
 * @param {string|TritArray} address — e.g. "1TT100" or TritArray instance
 * @returns {{ seed: Uint8Array, index: number }|null}
 */
export function getSeedByTritAddress(address) {
  return seedStore.getSeedByTritAddress(address);
}

/**
 * Run batch quality consensus across all satellite seeds.
 * Returns TritArray majority verdict and per-family counts.
 * 
 * @returns {{ majority: Trit, counts: Object, total: number }}
 */
export function batchQualityConsensus() {
  return seedStore.batchQualityConsensus();
}

/**
 * Get STEADYWATCH status and telemetry.
 */
export function getStatus() {
  return {
    ...seedStore.getStatus(),
    sentinel: {
      modelLoaded: sentinel._modelLoaded,
      provider: sentinel._inferenceEngine?.provider || 'none',
    },
  };
}

export { 
  SteadywatchSeedStore, EntropySentinel, 
  SATELLITE_COUNTS, MIN_ENTROPY_RATIO,
  TRIT_ADDRESS_LENGTH, FAMILY_GROUPS,
};

export default {
  initialize,
  getHybridSeed,
  scoreEntropy,
  selectByFibonacciCycle,
  getSeedByTritAddress,
  batchQualityConsensus,
  getStatus,
  seedStore,
  sentinel,
};
