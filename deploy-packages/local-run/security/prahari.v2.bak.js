/**
 * PRAHARI v2 — Mesh-Consensus Entropy Engine
 * 
 * Replaces STEADYWATCH with a pluggable, locally-sourced entropy system.
 * Instead of IBM Quantum hardware seeds, PRAHARI harvests entropy from
 * the mesh network itself and local hardware sources:
 * 
 *   1. RDRAND/RDSEED (CPU hardware RNG — AMD Ryzen 7 8700F)
 *   2. GPS jitter (MA-902 SNMP timing residuals via MANI)
 *   3. Interrupt timing (process.hrtime.bigint() deltas)
 *   4. Mesh packet arrival (WebSocket message interarrival jitter)
 *   5. OS CSPRNG (crypto.randomBytes — always available)
 * 
 * Architecture:
 *   - SHA3-256 sponge mixing pool absorbs entropy from all sources
 *   - Domain-separated expansion: SHA3(pool || "PRAHARI-0") || SHA3(pool || "PRAHARI-1")
 *   - Two-source extractor preserved: expanded ⊕ CSPRNG(64)
 *   - Pluggable sources register dynamically (lazy — subsystems come online at different boot stages)
 *   - EntropySentinel kept as-is (ONNX model + software fallback)
 *   - TRIBHUJ ternary quality scoring kept as-is
 *   - SST family grouping adapted for entropy pool slots
 * 
 * Key insight: Yakmesh IS a mesh network. The mesh itself is an entropy source.
 * As network grows, entropy quality improves — the opposite of centralized systems.
 * 
 * API contract: Drop-in replacement for steadywatch.js.
 *   initialize(options) → Promise<{initialized, seedCount, sentinel}>
 *   getHybridSeed() → Uint8Array(64)
 *   scoreEntropy(data) → Promise<{score, verdict, method, details}>
 *   getStatus() → full status object
 *   seedStore.initialized → boolean (checked by annex.js)
 * 
 * @module security/prahari
 * @license MIT
 * @copyright 2026 YAKMESH Contributors
 */

import { randomBytes } from 'crypto';
import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'fs';
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

const log = createLogger('security:prahari');

const __dirname = dirname(fileURLToPath(import.meta.url));

// ===================================================================
// CONSTANTS
// ===================================================================

/** Entropy pool slot counts — mirrors STEADYWATCH satellite counts for API compat */
const POOL_SLOT_COUNTS = Object.freeze({
    5: 144,   // 24 * (5 + 1) — default: 144 pool slots
    13: 336,   // 24 * (13 + 1) — future expansion
    17: 432,   // 24 * (17 + 1) — future expansion
});

// Re-export with legacy name for API compatibility
const SATELLITE_COUNTS = POOL_SLOT_COUNTS;

/** Each pool slot holds 256 bits */
const SEED_BYTES = 32;
/** Output size for ML-KEM-768 keygen */
const KEYGEN_SEED_BYTES = 64;
/** Minimum acceptable entropy score */
const MIN_ENTROPY_RATIO = 0.75;

// ═══ TERNARY CONSTANTS ═══

/** 6-trit address space for pool slot indexing (same as STEADYWATCH) */
const TRIT_ADDRESS_LENGTH = 6;

/** SST family group template */
const FAMILY_GROUPS = Object.freeze({
    [SSTFamily.A]: [],
    [SSTFamily.B]: [],
    [SSTFamily.C]: [],
});

// ═══ ENTROPY SOURCE TYPES ═══

/** Registered entropy source kinds */
const SourceKind = Object.freeze({
    RDRAND: 'rdrand',       // CPU hardware RNG (RDRAND/RDSEED)
    GPS: 'gps-jitter',   // MA-902 GPS timing jitter
    INTERRUPT: 'interrupt',    // process.hrtime() interarrival deltas
    MESH: 'mesh-arrival', // WebSocket message arrival jitter
    CSPRNG: 'csprng',       // OS crypto.randomBytes (always present)
});

// ═══ POOL MIXING ═══

/** Domain separation labels for SHA3 sponge expansion */
const DOMAIN_EXPAND_0 = Buffer.from('PRAHARI-0');
const DOMAIN_EXPAND_1 = Buffer.from('PRAHARI-1');
const DOMAIN_ABSORB = Buffer.from('PRAHARI-ABSORB');
const DOMAIN_RESEED = Buffer.from('PRAHARI-RESEED');

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
    // Source contribution tracking
    sourceContributions: {
        [SourceKind.RDRAND]: 0,
        [SourceKind.GPS]: 0,
        [SourceKind.INTERRUPT]: 0,
        [SourceKind.MESH]: 0,
        [SourceKind.CSPRNG]: 0,
    },
    poolReseeds: 0,
    lastReseedAt: null,
    // Ternary telemetry (preserved from STEADYWATCH)
    familySelections: { A: 0, B: 0, C: 0 },
    fibonacciCyclePosition: 0,
    ternaryQualityVerdicts: { positive: 0, neutral: 0, negative: 0 },
    tritAddressLookups: 0,
    batchConsensusRuns: 0,
};

// ===================================================================
// ENTROPY SOURCE REGISTRY
// ===================================================================

/**
 * Pluggable entropy source interface.
 * Sources register dynamically as subsystems come online.
 * 
 * @typedef {Object} EntropySource
 * @property {string} kind — SourceKind identifier
 * @property {string} name — Human-readable name
 * @property {() => Uint8Array | null} harvest — Collect entropy bytes (null = unavailable)
 * @property {() => boolean} available — Whether source is currently online
 * @property {number} weight — Relative contribution weight (1-10)
 */

class EntropySourceRegistry {
    constructor() {
        /** @type {Map<string, EntropySource>} */
        this._sources = new Map();
    }

    /**
     * Register a new entropy source.
     * @param {EntropySource} source
     */
    register(source) {
        if (!source.kind || !source.harvest) {
            log.warn('Invalid entropy source registration (missing kind or harvest)');
            return false;
        }
        this._sources.set(source.kind, source);
        log.info(`Entropy source registered: ${source.kind} (${source.name || 'unnamed'}, weight=${source.weight || 1})`);
        return true;
    }

    /**
     * Unregister an entropy source.
     * @param {string} kind
     */
    unregister(kind) {
        return this._sources.delete(kind);
    }

    /**
     * Harvest entropy from all available sources.
     * Returns array of { kind, data } pairs.
     * @returns {{ kind: string, data: Uint8Array }[]}
     */
    harvestAll() {
        const results = [];
        for (const [kind, source] of this._sources) {
            try {
                if (!source.available || source.available()) {
                    const data = source.harvest();
                    if (data && data.length > 0) {
                        results.push({ kind, data });
                        telemetry.sourceContributions[kind] = (telemetry.sourceContributions[kind] || 0) + 1;
                    }
                }
            } catch (err) {
                log.trace(`Entropy source ${kind} harvest failed: ${err.message}`);
            }
        }
        return results;
    }

    /**
     * Get status of all registered sources.
     */
    getStatus() {
        const status = {};
        for (const [kind, source] of this._sources) {
            status[kind] = {
                name: source.name || kind,
                available: source.available ? source.available() : true,
                weight: source.weight || 1,
                contributions: telemetry.sourceContributions[kind] || 0,
            };
        }
        return status;
    }

    get size() {
        return this._sources.size;
    }
}

// ===================================================================
// BUILT-IN ENTROPY SOURCES
// ===================================================================

/**
 * Interrupt timing source — harvests high-resolution timer jitter.
 * process.hrtime.bigint() nanosecond deltas between successive calls
 * contain genuine hardware timing noise from CPU TLB, cache, branch prediction.
 */
function createInterruptSource() {
    let lastTime = process.hrtime.bigint();

    return {
        kind: SourceKind.INTERRUPT,
        name: 'CPU interrupt timing jitter',
        weight: 3,
        available: () => true,
        harvest() {
            const samples = [];
            // Collect 32 timing deltas
            for (let i = 0; i < 32; i++) {
                const now = process.hrtime.bigint();
                const delta = now - lastTime;
                lastTime = now;
                // Extract lowest byte of nanosecond delta (most jittery)
                samples.push(Number(delta & 0xFFn));
            }
            return new Uint8Array(samples);
        },
    };
}

/**
 * CSPRNG source — crypto.randomBytes. Always available, always strong.
 * This is the baseline that ensures PRAHARI never falls below OS CSPRNG quality.
 */
function createCSPRNGSource() {
    return {
        kind: SourceKind.CSPRNG,
        name: 'OS CSPRNG (crypto.randomBytes)',
        weight: 10,
        available: () => true,
        harvest() {
            return randomBytes(32);
        },
    };
}

// ===================================================================
// PRAHARI ENTROPY POOL
// ===================================================================

/**
 * PrahariEntropyPool — SHA3 sponge-based entropy mixing pool.
 * 
 * Drop-in replacement for SteadywatchSeedStore.
 * Instead of static quantum hardware seeds, maintains a living entropy pool
 * that absorbs contributions from multiple hardware sources.
 * 
 * The pool holds N "slots" (default 144) that are continuously refreshed.
 * Each slot is a 256-bit value derived from mixed entropy.
 * Slots are organized into SST families and addressed with 6-trit codes,
 * preserving the ternary-144 selection logic from STEADYWATCH.
 */
class PrahariEntropyPool {
    constructor() {
        /** @type {Uint8Array[]} Pool of 256-bit entropy slots */
        this.seeds = [];
        /** Current rotation index */
        this.rotationIndex = 0;
        /** Pool generation prime (for slot count: 24*(p+1)) */
        this.prime = 0;
        /** Pool metadata */
        this.metadata = null;
        /** Whether pool is initialized */
        this.initialized = false;
        /** Node-specific slot assignment */
        this.nodeAssignment = -1;
        /** Quality scores per slot */
        this.qualityScores = new Map();
        /** Entropy source registry */
        this.sources = new EntropySourceRegistry();

        // ═══ SPONGE STATE ═══
        /** 
         * SHA3-256 sponge accumulator — absorbs all entropy contributions.
         * Never revealed directly; only squeezed through domain-separated expansion.
         * @type {Uint8Array}
         */
        this._spongeState = randomBytes(64);
        /** Absorption counter */
        this._absorbCount = 0;

        // ═══ TERNARY-144 STATE (preserved from STEADYWATCH) ═══

        /** SST family groups — slot indices by digital root family */
        this.familyGroups = { A: [], B: [], C: [] };
        /** 6-trit balanced ternary address per slot */
        this.tritAddresses = new Map();
        /** Reverse lookup: trit string → slot index */
        this.tritIndex = new Map();
        /** Ternary quality verdicts per slot */
        this.qualityVerdicts = new Map();
        /** Fibonacci 24-cycle position */
        this.fibCyclePos = 0;

        // ═══ RESEED TIMER ═══
        this._reseedTimer = null;
        this._reseedIntervalMs = 10_000; // Reseed pool every 10 seconds
    }

    // ===================================================================
    // SPONGE OPERATIONS
    // ===================================================================

    /**
     * Absorb entropy into the sponge state.
     * SHA3-256(spongeState || domain || newEntropy) → new sponge state
     * 
     * @param {Uint8Array} data — entropy contribution
     * @param {Buffer} [domain] — domain separation label
     */
    _absorb(data, domain = DOMAIN_ABSORB) {
        const input = Buffer.concat([
            Buffer.from(this._spongeState),
            domain,
            Buffer.from(data),
        ]);
        // SHA3-256 of concatenation → new 32-byte state
        const hash = sha3_256(input);
        // Expand state to 64 bytes: hash || SHA3(hash || counter)
        const counterBuf = Buffer.alloc(4);
        counterBuf.writeUInt32BE(this._absorbCount, 0);
        const extend = sha3_256(Buffer.concat([Buffer.from(hash), counterBuf]));
        this._spongeState = new Uint8Array(64);
        this._spongeState.set(hash, 0);
        this._spongeState.set(extend, 32);
        this._absorbCount++;
    }

    /**
     * Squeeze N bytes from the sponge (domain-separated).
     * Does NOT reveal the sponge state — produces derived output only.
     * 
     * @param {number} bytes — number of output bytes (must be multiple of 32)
     * @param {string} label — domain separation label
     * @returns {Uint8Array}
     */
    _squeeze(bytes, label = 'SQUEEZE') {
        const chunks = Math.ceil(bytes / 32);
        const out = new Uint8Array(bytes);
        for (let i = 0; i < chunks; i++) {
            const domainBuf = Buffer.from(`${label}-${i}`);
            const input = Buffer.concat([
                Buffer.from(this._spongeState),
                domainBuf,
            ]);
            const chunk = sha3_256(input);
            const offset = i * 32;
            const copyLen = Math.min(32, bytes - offset);
            out.set(chunk.subarray(0, copyLen), offset);
        }
        return out;
    }

    /**
     * Generate a pool slot value from current sponge state.
     * @param {number} slotIndex
     * @returns {Uint8Array} — 32-byte slot value
     */
    _generateSlot(slotIndex) {
        const label = `PRAHARI-SLOT-${slotIndex}`;
        return this._squeeze(SEED_BYTES, label);
    }

    // ===================================================================
    // INITIALIZATION
    // ===================================================================

    /**
     * Initialize the entropy pool with N slots.
     * 
     * 1. Register built-in entropy sources (interrupt timing, CSPRNG)
     * 2. Harvest initial entropy from all available sources
     * 3. Absorb into sponge
     * 4. Generate pool slots from sponge
     * 5. Build ternary structures (family groups, trit addresses)
     * 
     * @param {number} prime — pool prime (5, 13, 17) determining slot count
     * @param {string} [persistPath] — optional path to persist pool state
     * @returns {boolean}
     */
    initializePool(prime = 5, persistPath = null) {
        const count = POOL_SLOT_COUNTS[prime];
        if (!count) {
            log.error('Invalid prime ' + prime + '. Use 5, 13, or 17.');
            return false;
        }

        this.prime = prime;
        log.info(`PRAHARI: Initializing entropy pool (p=${prime}, ${count} slots)`);

        // Register built-in sources
        this.sources.register(createInterruptSource());
        this.sources.register(createCSPRNGSource());

        // Initial entropy harvest — absorb all available sources
        this._harvestAndAbsorb();

        // Add extra initial entropy from high-res timer spread
        const initEntropy = Buffer.alloc(64);
        for (let i = 0; i < 64; i++) {
            const t = process.hrtime.bigint();
            initEntropy[i] = Number(t & 0xFFn);
        }
        this._absorb(initEntropy, DOMAIN_RESEED);

        // Try loading persisted pool state (if available)
        let loadedPersisted = false;
        if (persistPath && existsSync(persistPath)) {
            loadedPersisted = this._loadPersistedState(persistPath);
        }

        if (!loadedPersisted) {
            // Generate fresh pool slots from sponge state
            this.seeds = [];
            for (let i = 0; i < count; i++) {
                this.seeds.push(this._generateSlot(i));
            }
        }

        this.metadata = {
            prime,
            backend: 'prahari-mesh-entropy',
            validated: new Date().toISOString().split('T')[0],
            loadedAt: new Date().toISOString(),
            seedCount: this.seeds.length,
            sources: Array.from(this.sources._sources.keys()),
        };

        telemetry.seedsLoaded = this.seeds.length;
        this.initialized = this.seeds.length > 0;

        // Run quality checks on all slots
        for (let i = 0; i < this.seeds.length; i++) {
            this._checkBias(this.seeds[i], i);
        }

        // Build ternary structures
        if (this.initialized) {
            this._buildTernaryStructures();
        }

        // Persist initial state
        if (persistPath && this.initialized) {
            this._persistState(persistPath);
        }

        // Start periodic reseed timer
        this._startReseedTimer(persistPath);

        log.info(`PRAHARI: Pool initialized — ${this.seeds.length} slots, ${this.sources.size} entropy sources`);
        return this.initialized;
    }

    /**
     * Load persisted pool state from JSON.
     * @private
     */
    _loadPersistedState(path) {
        try {
            const raw = readFileSync(path, 'utf-8');
            const data = JSON.parse(raw);
            if (!data.seeds || !Array.isArray(data.seeds)) return false;

            const expectedCount = POOL_SLOT_COUNTS[data.prime || this.prime];
            if (expectedCount && data.seeds.length !== expectedCount) {
                log.warn(`Persisted pool size mismatch: expected ${expectedCount}, got ${data.seeds.length}`);
            }

            // Parse hex seeds and absorb them into sponge for continuity
            this.seeds = [];
            for (const hex of data.seeds) {
                if (hex.length === SEED_BYTES * 2) {
                    const bytes = hexToUint8(hex);
                    this.seeds.push(bytes);
                    // Absorb persisted material to advance sponge state
                    this._absorb(bytes, DOMAIN_RESEED);
                }
            }

            if (data.spongeState) {
                // Also absorb old sponge state for backward secrecy
                this._absorb(hexToUint8(data.spongeState), DOMAIN_RESEED);
            }

            log.info(`PRAHARI: Loaded ${this.seeds.length} persisted pool slots`);
            return this.seeds.length > 0;
        } catch (err) {
            log.warn('Failed to load persisted PRAHARI state: ' + err.message);
            return false;
        }
    }

    /**
     * Persist current pool state to JSON.
     * @private
     */
    _persistState(path) {
        try {
            const dir = dirname(path);
            if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

            const data = {
                prime: this.prime,
                slotCount: this.seeds.length,
                backend: 'prahari-mesh-entropy',
                persistedAt: new Date().toISOString(),
                absorbCount: this._absorbCount,
                // Only persist SHA3 of sponge state — not the raw state
                spongeState: Buffer.from(sha3_256(Buffer.from(this._spongeState))).toString('hex'),
                seeds: this.seeds.map(s => Buffer.from(s).toString('hex')),
            };

            writeFileSync(path, JSON.stringify(data, null, 2));
            log.trace('PRAHARI: Pool state persisted to ' + path);
        } catch (err) {
            log.warn('Failed to persist PRAHARI state: ' + err.message);
        }
    }

    // ===================================================================
    // ENTROPY HARVESTING & RESEED
    // ===================================================================

    /**
     * Harvest entropy from all registered sources and absorb into sponge.
     * @private
     */
    _harvestAndAbsorb() {
        const contributions = this.sources.harvestAll();
        for (const { kind, data } of contributions) {
            const domain = Buffer.from(`PRAHARI-SRC-${kind}`);
            this._absorb(data, domain);
        }
        return contributions.length;
    }

    /**
     * Reseed the pool — harvest fresh entropy and update all slots.
     * Called periodically by the reseed timer.
     * 
     * Strategy: Don't replace all slots at once (would spike CPU).
     * Instead, refresh 1/12 of slots per reseed cycle (12 slots for 144-slot pool).
     * Full pool refresh takes ~2 minutes at 10s interval.
     */
    reseed(persistPath = null) {
        if (!this.initialized) return;

        // Harvest from all sources
        const sourceCount = this._harvestAndAbsorb();
        if (sourceCount === 0) {
            // No sources available — absorb CSPRNG directly
            this._absorb(randomBytes(32), DOMAIN_RESEED);
        }

        // Refresh a fraction of pool slots
        const slotsPerCycle = Math.max(1, Math.ceil(this.seeds.length / 12));
        const startSlot = (telemetry.poolReseeds * slotsPerCycle) % this.seeds.length;

        for (let i = 0; i < slotsPerCycle; i++) {
            const slotIdx = (startSlot + i) % this.seeds.length;
            const oldSlot = this.seeds[slotIdx];
            const newSlot = this._generateSlot(slotIdx);

            // XOR old and new to preserve any residual entropy
            for (let b = 0; b < SEED_BYTES; b++) {
                newSlot[b] ^= oldSlot[b];
            }
            this.seeds[slotIdx] = newSlot;

            // Re-check quality
            this._checkBias(newSlot, slotIdx);
        }

        telemetry.poolReseeds++;
        telemetry.lastReseedAt = new Date().toISOString();

        // Persist periodically (every 6 reseeds = ~60 seconds)
        if (persistPath && telemetry.poolReseeds % 6 === 0) {
            this._persistState(persistPath);
        }

        log.trace(`PRAHARI: Reseed #${telemetry.poolReseeds} — refreshed ${slotsPerCycle} slots from ${sourceCount} sources`);
    }

    /**
     * Start periodic reseed timer.
     * @private
     */
    _startReseedTimer(persistPath = null) {
        if (this._reseedTimer) clearInterval(this._reseedTimer);
        this._reseedTimer = setInterval(() => this.reseed(persistPath), this._reseedIntervalMs);
        if (this._reseedTimer.unref) this._reseedTimer.unref();
    }

    /**
     * Stop reseed timer (for cleanup).
     */
    stopReseed() {
        if (this._reseedTimer) {
            clearInterval(this._reseedTimer);
            this._reseedTimer = null;
        }
    }

    // ===================================================================
    // SEED STORE COMPAT — Mirrors SteadywatchSeedStore API
    // ===================================================================

    /**
     * Load seeds from a JSON file (backward compatibility).
     * PRAHARI can also bootstrap from a persisted pool file.
     * @param {string} seedFilePath
     * @returns {boolean}
     */
    load(seedFilePath) {
        return this._loadPersistedState(seedFilePath);
    }

    /**
     * Generate test pool slots (backward compatible with generateTestSeeds).
     * Creates deterministic slots using SHA3 of sequential inputs.
     * 
     * @param {number} prime — pool prime
     * @param {string} [outputPath] — save to file
     * @returns {boolean}
     */
    generateTestSeeds(prime = 5, outputPath = null) {
        const count = POOL_SLOT_COUNTS[prime];
        if (!count) {
            log.error('Invalid prime ' + prime + '. Use 5, 13, or 17.');
            return false;
        }

        log.info(`PRAHARI: Generating ${count} test pool slots for p=${prime}`);

        // Use PRAHARI's own sponge to generate deterministic but well-mixed slots
        this._absorb(Buffer.from(`PRAHARI-TEST-INIT-p${prime}`), DOMAIN_RESEED);

        this.seeds = [];
        for (let i = 0; i < count; i++) {
            this.seeds.push(this._generateSlot(i));
        }

        const data = {
            prime,
            slotCount: count,
            backend: 'prahari-mesh-entropy',
            validated: new Date().toISOString().split('T')[0],
            note: 'PRAHARI test pool slots — locally generated from SHA3 sponge',
            seeds: this.seeds.map(s => Buffer.from(s).toString('hex')),
        };

        if (outputPath) {
            const dir = dirname(outputPath);
            if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
            writeFileSync(outputPath, JSON.stringify(data, null, 2));
            log.info('PRAHARI: Test pool written to ' + outputPath);
        }

        this.prime = prime;
        this.metadata = {
            prime,
            backend: 'prahari-mesh-entropy',
            validated: data.validated,
            seedCount: count,
            loadedAt: new Date().toISOString(),
            sources: Array.from(this.sources._sources.keys()),
        };
        this.initialized = true;
        telemetry.seedsLoaded = count;

        // Quality checks
        for (let i = 0; i < this.seeds.length; i++) {
            this._checkBias(this.seeds[i], i);
        }

        // Build ternary structures
        if (this.initialized) {
            this._buildTernaryStructures();
        }

        return true;
    }

    /**
     * Assign this node a specific pool slot index.
     * @param {number} index
     */
    assignNode(index) {
        if (index < 0 || index >= this.seeds.length) {
            log.error('Invalid node assignment: ' + index + ' (have ' + this.seeds.length + ' slots)');
            return;
        }
        this.nodeAssignment = index;
        this.rotationIndex = index;
        log.info('Node assigned to slot ' + index + ' (fingerprint: ' + sha3_256hex(this.seeds[index]).slice(0, 16) + '...)');
    }

    // ===================================================================
    // HYBRID SEED GENERATION
    // ===================================================================

    /**
     * Get a hybrid seed suitable for ML-KEM-768 keygen.
     * 
     * Algorithm (PRAHARI Mesh-Entropy):
     *   1. Advance Fibonacci 24-cycle position
     *   2. Determine SST family for this position
     *   3. Select pool slot from matching family group
     *   4. Generate 64 bytes from OS CSPRNG
     *   5. Expand pool slot to 64 bytes: SHA3(slot || "PRAHARI-0") || SHA3(slot || "PRAHARI-1")
     *   6. XOR: hybridSeed = expanded ⊕ CSPRNG(64)
     *   7. Return 64-byte hybrid seed
     * 
     * Security property: Two-source extractor — even if the pool is fully
     * compromised, CSPRNG ensures the hybrid seed retains entropy.
     * Even if CSPRNG is compromised, the pool (fed by multiple hardware
     * sources + mesh jitter) ensures entropy.
     * 
     * @returns {Uint8Array} — 64-byte hybrid seed
     */
    getHybridSeed() {
        if (!this.initialized || this.seeds.length === 0) {
            log.trace('PRAHARI not initialized, falling back to pure CSPRNG');
            return randomBytes(KEYGEN_SEED_BYTES);
        }

        // ═══ TERNARY: Fibonacci-cycle family-aware slot selection ═══
        let slotIndex;

        if (this.nodeAssignment >= 0) {
            slotIndex = this.nodeAssignment;
        } else if (this.familyGroups.A.length > 0) {
            // Use Fibonacci 24-cycle to pick SST family, round-robin within
            const fibRoot = fibonacciRoot(this.fibCyclePos);
            const family = getFamily(fibRoot);
            const familyGroup = this.familyGroups[family];

            if (familyGroup.length > 0) {
                const familyOffset = this.rotationIndex % familyGroup.length;
                slotIndex = familyGroup[familyOffset];
                telemetry.familySelections[family]++;
            } else {
                slotIndex = this.rotationIndex;
            }

            this.fibCyclePos = (this.fibCyclePos + 1) % 24;
            telemetry.fibonacciCyclePosition = this.fibCyclePos;
        } else {
            slotIndex = this.rotationIndex;
        }

        const poolSlot = this.seeds[slotIndex % this.seeds.length];

        // Rotate
        this.rotationIndex = (this.rotationIndex + 1) % this.seeds.length;
        telemetry.rotations++;

        // Expand 32-byte pool slot to 64 bytes using SHA3 (ACCEL: native SHA-NI)
        const expand0 = sha3_256(Buffer.concat([
            Buffer.from(poolSlot),
            DOMAIN_EXPAND_0,
        ]));
        const expand1 = sha3_256(Buffer.concat([
            Buffer.from(poolSlot),
            DOMAIN_EXPAND_1,
        ]));
        const expandedSlot = new Uint8Array(KEYGEN_SEED_BYTES);
        expandedSlot.set(expand0, 0);
        expandedSlot.set(expand1, 32);

        // CSPRNG contribution
        const csprng = randomBytes(KEYGEN_SEED_BYTES);

        // XOR: two-source extractor
        const hybridSeed = new Uint8Array(KEYGEN_SEED_BYTES);
        for (let i = 0; i < KEYGEN_SEED_BYTES; i++) {
            hybridSeed[i] = expandedSlot[i] ^ csprng[i];
        }

        telemetry.hybridSeeds++;
        telemetry.lastSeedIndex = slotIndex;

        log.trace('Hybrid seed generated (slot ' + slotIndex +
            ', family ' + getFamilyOf(slotIndex) +
            ', fibPos ' + this.fibCyclePos +
            ', rotation ' + this.rotationIndex + ')');
        return hybridSeed;
    }

    // ===================================================================
    // TERNARY QUALITY CHECK
    // ===================================================================

    /**
     * Evaluate a slot's entropy quality as a balanced ternary verdict.
     *   POSITIVE (+1): Excellent entropy
     *   NEUTRAL  ( 0): Acceptable entropy
     *   NEGATIVE (-1): Biased/rejected
     * 
     * @param {Uint8Array} slotBytes — 256-bit pool slot
     * @param {number} index — slot index
     * @returns {Trit}
     */
    _checkBiasTernary(slotBytes, index) {
        let zeros = 0;
        let ones = 0;
        const byteSet = new Set();

        for (const b of slotBytes) {
            if (b === 0x00) zeros++;
            if (b === 0xFF) ones++;
            byteSet.add(b);
        }

        // NEGATIVE: Severe bias
        if (zeros > SEED_BYTES * 0.5) {
            log.warn('Slot ' + index + ': NEGATIVE — excessive zero bytes (' + zeros + '/' + SEED_BYTES + ')');
            telemetry.ternaryQualityVerdicts.negative++;
            return new Trit(NEGATIVE);
        }
        if (ones > SEED_BYTES * 0.5) {
            log.warn('Slot ' + index + ': NEGATIVE — excessive 0xFF bytes (' + ones + '/' + SEED_BYTES + ')');
            telemetry.ternaryQualityVerdicts.negative++;
            return new Trit(NEGATIVE);
        }
        if (byteSet.size < SEED_BYTES * 0.25) {
            log.warn('Slot ' + index + ': NEGATIVE — low byte diversity (' + byteSet.size + ' unique)');
            telemetry.ternaryQualityVerdicts.negative++;
            return new Trit(NEGATIVE);
        }

        // POSITIVE: Excellent
        if (byteSet.size >= SEED_BYTES * 0.75 && zeros <= 2 && ones <= 2) {
            telemetry.ternaryQualityVerdicts.positive++;
            return new Trit(POSITIVE);
        }

        // NEUTRAL: Acceptable
        telemetry.ternaryQualityVerdicts.neutral++;
        return new Trit(NEUTRAL);
    }

    /**
     * Backward-compatible wrapper — returns boolean for load().
     * @private
     */
    _checkBias(slotBytes, index) {
        const verdict = this._checkBiasTernary(slotBytes, index);
        this.qualityVerdicts.set(index, verdict);
        return !verdict.isNegative;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TERNARY-144: SST FAMILY GROUPING (preserved from STEADYWATCH)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Classify all pool slots into SST family groups.
     */
    _buildFamilyGroups() {
        this.familyGroups = { A: [], B: [], C: [] };
        for (let i = 0; i < this.seeds.length; i++) {
            const family = getFamilyOf(i + 1);
            this.familyGroups[family].push(i);
        }
        log.info('SST family groups: A=' + this.familyGroups.A.length +
            ' B=' + this.familyGroups.B.length +
            ' C=' + this.familyGroups.C.length);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TERNARY-144: 6-TRIT ADDRESSES (preserved from STEADYWATCH)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Assign each slot a 6-trit balanced ternary address.
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
            ' slots in 6-trit space (capacity: 3^5=' + Math.pow(3, 5) + ')');
    }

    /**
     * Look up a slot by its 6-trit address.
     * @param {TritArray | string} address
     * @returns {{ index: number, seed: Uint8Array } | null}
     */
    getSeedByTritAddress(address) {
        telemetry.tritAddressLookups++;
        const key = address instanceof TritArray ? address.toString() : address;
        const index = this.tritIndex.get(key);
        if (index === undefined) return null;
        return { index, seed: this.seeds[index] ?? null };
    }

    /**
     * Get the 6-trit address for a slot index.
     * @param {number} index
     * @returns {TritArray | null}
     */
    getTritAddress(index) {
        return this.tritAddresses.get(index) ?? null;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BATCH CONSENSUS (preserved from STEADYWATCH)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Validate batch quality verdicts using TritArray consensus.
     * @returns {{ majority: Trit, counts: Object, total: number, balanced: boolean }}
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
            log.warn('PRAHARI batch consensus: NEGATIVE — pool quality may be degraded');
        } else if (majority.isPositive) {
            log.info('PRAHARI batch consensus: POSITIVE — excellent pool quality');
        }

        return { majority, counts, total: verdicts.length, balanced };
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FAMILY-AWARE SELECTION (preserved from STEADYWATCH)
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Select a slot from a specific SST family.
     * @param {string} family — 'A', 'B', or 'C'
     * @param {number} [offset=0]
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
     * Select a slot using Fibonacci 24-cycle family mapping.
     * @returns {{ index: number, seed: Uint8Array, family: string, fibPosition: number, fibRoot: number }}
     */
    selectByFibonacciCycle() {
        const pos = this.fibCyclePos;
        const root = fibonacciRoot(pos);
        const family = getFamily(root);
        const familyTrit = toFamilyTrit(root);

        const group = this.familyGroups[family];
        if (!group || group.length === 0) {
            return {
                index: this.rotationIndex % this.seeds.length,
                seed: this.seeds[this.rotationIndex % this.seeds.length],
                family,
                fibPosition: pos,
                fibRoot: root,
            };
        }

        const familyOffset = this.rotationIndex % group.length;
        const index = group[familyOffset];

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
     * Build all ternary structures after pool initialization.
     * @private
     */
    _buildTernaryStructures() {
        this._buildFamilyGroups();
        this._buildTritAddresses();

        const totalDR = digitalRoot(this.seeds.length);
        const totalFamily = getFamily(totalDR);
        const totalTrit = toFamilyTrit(this.seeds.length);

        log.info('Ternary-144: DR(' + this.seeds.length + ')=' + totalDR +
            ' → Family ' + totalFamily +
            ' → TRIT ' + totalTrit.toChar() +
            ' | constellation address: ' + TritArray.fromDecimal(this.seeds.length, TRIT_ADDRESS_LENGTH).toString());
    }

    /**
     * Get status report.
     */
    getStatus() {
        let consensus = null;
        if (this.qualityVerdicts.size > 0) {
            consensus = this.batchQualityConsensus();
            consensus.majority = consensus.majority.toChar();
        }

        return {
            initialized: this.initialized,
            prime: this.prime,
            seedCount: this.seeds.length,
            nodeAssignment: this.nodeAssignment,
            rotationIndex: this.rotationIndex,
            metadata: this.metadata,
            telemetry: { ...telemetry },
            // Entropy source status
            sources: this.sources.getStatus(),
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
// (Preserved from STEADYWATCH — this code is MIT and works perfectly)
// ===================================================================

/**
 * Entropy Sentinel uses the ACCEL InferenceEngine (NPU/GPU/CPU) to
 * score the quality of entropy material before it enters keygen.
 * 
 * NPU path: ONNX model for pattern detection
 * CPU path: bit-entropy + byte frequency chi-square
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
     * Convert numeric score to TRIBHUJ ternary verdict.
     * ≥ 0.85 → POSITIVE | ≥ 0.50 → NEUTRAL | < 0.50 → NEGATIVE
     * @param {number} score
     * @returns {Trit}
     */
    _scoreToVerdict(score) {
        if (score >= 0.85) return new Trit(POSITIVE);
        if (score >= 0.50) return new Trit(NEUTRAL);
        return new Trit(NEGATIVE);
    }

    /**
     * Score entropy quality of a byte sequence.
     * NPU path: ONNX model | CPU path: bit-entropy + chi-square
     * 
     * @param {Uint8Array} data
     * @returns {Promise<{ score: number, verdict: Trit, method: string, details: Object }>}
     */
    async score(data) {
        telemetry.sentinelChecks++;

        // Try NPU/GPU inference first
        if (this._modelLoaded && this._inferenceEngine) {
            try {
                const MODEL_INPUTS = 32;
                const inputTensor = new Float32Array(MODEL_INPUTS);
                if (data.length <= MODEL_INPUTS) {
                    for (let i = 0; i < data.length; i++) inputTensor[i] = data[i] / 255.0;
                } else {
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

        // Software fallback
        return this._softwareScore(data);
    }

    /**
     * Software statistical scoring (no NPU required).
     * @private
     */
    _softwareScore(data) {
        const len = data.length;
        if (len === 0) return { score: 0, verdict: new Trit(NEGATIVE), method: 'cpu', details: {} };

        // 1. Bit-entropy
        const freq = new Uint32Array(256);
        for (const b of data) freq[b]++;

        let bitEntropy = 0;
        for (let i = 0; i < 256; i++) {
            if (freq[i] === 0) continue;
            const p = freq[i] / len;
            bitEntropy -= p * Math.log2(p);
        }
        const entropyNorm = bitEntropy / 8.0;

        // 2. Chi-square
        const expected = len / 256;
        let chiSquare = 0;
        for (let i = 0; i < 256; i++) {
            const diff = freq[i] - expected;
            chiSquare += (diff * diff) / expected;
        }
        const chiNorm = Math.max(0, 1 - chiSquare / 600);

        // 3. Run length
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

/** Global PRAHARI entropy pool (replaces STEADYWATCH seedStore) */
export const seedStore = new PrahariEntropyPool();

/** Global Entropy Sentinel */
export const sentinel = new EntropySentinel();

/**
 * Initialize PRAHARI subsystem.
 * Drop-in replacement for steadywatch.initialize().
 * 
 * @param {Object} options
 * @param {string} [options.seedFile] — path to persisted pool state
 * @param {number} [options.nodeIndex] — assigned pool slot index
 * @param {number} [options.prime=5] — pool prime (determines slot count)
 * @param {boolean} [options.generateTest=false] — generate test slots if no file
 * @param {import('../utils/accel.js').InferenceEngine} [options.inferenceEngine] — ACCEL inference
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

    // Determine persist path
    const persistPath = seedFile || join(__dirname, '../data/prahari-pool-p' + prime + '.json');

    // Try loading persisted pool
    let loaded = false;
    if (persistPath && existsSync(persistPath)) {
        loaded = seedStore.load(persistPath);
        if (loaded) {
            seedStore.prime = prime;
            seedStore.initialized = true;
            telemetry.seedsLoaded = seedStore.seeds.length;
            // Rebuild ternary structures from loaded seeds
            seedStore._buildTernaryStructures();
            // Register built-in sources & start reseed
            seedStore.sources.register(createInterruptSource());
            seedStore.sources.register(createCSPRNGSource());
            seedStore._startReseedTimer(persistPath);
        }
    }

    if (!loaded) {
        // Initialize fresh pool with all built-in sources
        loaded = seedStore.initializePool(prime, persistPath);
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

    log.info('PRAHARI initialized:', status);
    return status;
}

/**
 * Register an external entropy source (e.g., GPS jitter, mesh arrival).
 * Called by other subsystems once they're online.
 * 
 * @param {EntropySource} source
 * @returns {boolean}
 */
export function registerEntropySource(source) {
    return seedStore.sources.register(source);
}

/**
 * Unregister an entropy source.
 * @param {string} kind
 * @returns {boolean}
 */
export function unregisterEntropySource(kind) {
    return seedStore.sources.unregister(kind);
}

/**
 * Get a hybrid entropy+CSPRNG seed for ML-KEM-768 keygen.
 * Drop-in replacement for steadywatch.getHybridSeed().
 * 
 * @returns {Uint8Array} — 64-byte seed
 */
export function getHybridSeed() {
    return seedStore.getHybridSeed();
}

/**
 * Score entropy quality of arbitrary byte data.
 * Uses NPU/GPU if available, software fallback otherwise.
 * 
 * @param {Uint8Array} data
 * @returns {Promise<{ score: number, verdict: Trit, method: string, details: Object }>}
 */
export async function scoreEntropy(data) {
    return sentinel.score(data);
}

/**
 * Select a seed using Fibonacci-cycle family-aware rotation.
 * @returns {{ seed: Uint8Array, index: number, family: string, fibPos: number, address: TritArray|null }}
 */
export function selectByFibonacciCycle() {
    return seedStore.selectByFibonacciCycle();
}

/**
 * Get seed by 6-trit balanced ternary address.
 * @param {string|TritArray} address
 * @returns {{ seed: Uint8Array, index: number }|null}
 */
export function getSeedByTritAddress(address) {
    return seedStore.getSeedByTritAddress(address);
}

/**
 * Run batch quality consensus across all pool slots.
 * @returns {{ majority: Trit, counts: Object, total: number }}
 */
export function batchQualityConsensus() {
    return seedStore.batchQualityConsensus();
}

/**
 * Get PRAHARI status and telemetry.
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

// ═══ CLASS & CONSTANT EXPORTS (API compatibility) ═══

// Export PrahariEntropyPool as SteadywatchSeedStore alias for test compatibility
export {
    PrahariEntropyPool,
    PrahariEntropyPool as SteadywatchSeedStore,
    EntropySentinel,
    EntropySourceRegistry,
    SourceKind,
    SATELLITE_COUNTS,
    POOL_SLOT_COUNTS,
    MIN_ENTROPY_RATIO,
    TRIT_ADDRESS_LENGTH,
    FAMILY_GROUPS,
};

export default {
    initialize,
    getHybridSeed,
    scoreEntropy,
    selectByFibonacciCycle,
    getSeedByTritAddress,
    batchQualityConsensus,
    getStatus,
    registerEntropySource,
    unregisterEntropySource,
    seedStore,
    sentinel,
};
