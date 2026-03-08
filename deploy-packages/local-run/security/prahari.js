/**
 * PRAHARI v3 — Pure Sponge Entropy Engine
 * 
 * Post-quantum mesh-consensus entropy engine. Replaces the v2 slot-array
 * design (inherited from STEADYWATCH) with a clean SHA3-256 sponge that
 * continuously absorbs entropy from multiple hardware sources.
 * 
 * v3 changes from v2:
 *   - REMOVED: 144-slot seed array (cargo from IBM Quantum era)
 *   - REMOVED: SST family grouping, Fibonacci cycle slot selection
 *   - REMOVED: 6-trit slot addressing, batch quality consensus
 *   - SIMPLIFIED: getHybridSeed() = squeeze(64) ⊕ CSPRNG(64)
 *   - SIMPLIFIED: Persistence = sponge state only (~128 bytes vs 4,608)
 *   - KEPT: Pluggable entropy source registry
 *   - KEPT: EntropySentinel (NPU/GPU/CPU quality scoring)
 *   - KEPT: TRIBHUJ ternary quality verdicts
 * 
 * Entropy sources:
 *   1. RDRAND/RDSEED (CPU hardware RNG — AMD Ryzen 7 8700F)
 *   2. GPS jitter (MA-902 SNMP timing residuals via MANI)
 *   3. Interrupt timing (process.hrtime.bigint() deltas)
 *   4. Mesh packet arrival (WebSocket message interarrival jitter)
 *   5. OS CSPRNG (crypto.randomBytes — always available)
 * 
 * Security property: Two-source extractor.
 *   hybridSeed = sponge.squeeze(64) ⊕ CSPRNG(64)
 *   Even if the sponge is fully compromised, CSPRNG ensures entropy.
 *   Even if CSPRNG is compromised, the sponge (fed by multiple sources) ensures entropy.
 * 
 * API contract (drop-in replacement for v2):
 *   initialize(options) → Promise<{initialized, sentinel}>
 *   getHybridSeed() → Uint8Array(64)
 *   scoreEntropy(data) → Promise<{score, verdict, method, details}>
 *   getStatus() → full status object
 *   registerEntropySource(source) → boolean
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
import { sha3_256 } from '../utils/accel.js';

// ═══ TRIBHUJ — Balanced ternary quality verdicts ═══
import { Trit, POSITIVE, NEUTRAL, NEGATIVE } from '../oracle/tribhuj.js';

const log = createLogger('security:prahari');

const __dirname = dirname(fileURLToPath(import.meta.url));

// ===================================================================
// CONSTANTS
// ===================================================================

/** Output size for ML-KEM-768 keygen */
const KEYGEN_SEED_BYTES = 64;
/** Minimum acceptable entropy score */
const MIN_ENTROPY_RATIO = 0.75;

// ═══ ENTROPY SOURCE TYPES ═══

/** Registered entropy source kinds */
const SourceKind = Object.freeze({
    RDRAND: 'rdrand',       // CPU hardware RNG (RDRAND/RDSEED)
    GPS: 'gps-jitter',   // MA-902 GPS timing jitter
    INTERRUPT: 'interrupt',    // process.hrtime() interarrival deltas
    MESH: 'mesh-arrival', // WebSocket message arrival jitter
    CSPRNG: 'csprng',       // OS crypto.randomBytes (always present)
});

// ═══ SPONGE MIXING ═══

/** Domain separation labels for SHA3 sponge */
const DOMAIN_ABSORB = Buffer.from('PRAHARI-ABSORB');
const DOMAIN_RESEED = Buffer.from('PRAHARI-RESEED');

// ===================================================================
// TELEMETRY
// ===================================================================

const telemetry = {
    hybridSeeds: 0,
    absorbCount: 0,
    sentinelChecks: 0,
    sentinelPasses: 0,
    sentinelFails: 0,
    // Source contribution tracking
    sourceContributions: {
        [SourceKind.RDRAND]: 0,
        [SourceKind.GPS]: 0,
        [SourceKind.INTERRUPT]: 0,
        [SourceKind.MESH]: 0,
        [SourceKind.CSPRNG]: 0,
    },
    reseedCycles: 0,
    lastReseedAt: null,
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
// PRAHARI v3 — PURE SPONGE ENGINE
// ===================================================================

/**
 * PrahariSpongeEngine — SHA3-256 sponge-based entropy pool.
 * 
 * v3 replaces the 144-slot seed array with a single sponge state.
 * Entropy is continuously absorbed from hardware sources and squeezed
 * on demand for key generation.
 * 
 * State: 64 bytes (two SHA3-256 blocks)
 * Output: squeeze(N, label) — domain-separated key derivation
 */
class PrahariSpongeEngine {
    constructor() {
        /** Whether engine is initialized */
        this.initialized = false;
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

        // ═══ RESEED TIMER ═══
        this._reseedTimer = null;
        this._reseedIntervalMs = 10_000; // Reseed every 10 seconds
        this._persistPath = null;
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
        telemetry.absorbCount = this._absorbCount;
    }

    /**
     * Squeeze N bytes from the sponge (domain-separated).
     * Does NOT reveal the sponge state — produces derived output only.
     * 
     * @param {number} bytes — number of output bytes
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

    // ===================================================================
    // INITIALIZATION
    // ===================================================================

    /**
     * Initialize the sponge engine.
     * 
     * 1. Register built-in entropy sources (interrupt timing, CSPRNG)
     * 2. Harvest initial entropy from all available sources
     * 3. Absorb into sponge
     * 4. Try loading persisted sponge state for continuity
     * 5. Start periodic reseed timer
     * 
     * @param {string} [persistPath] — optional path to persist sponge state
     * @returns {boolean}
     */
    initialize(persistPath = null) {
        this._persistPath = persistPath;
        log.info('PRAHARI v3: Initializing sponge engine');

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

        // Try loading persisted sponge state (if available)
        if (persistPath && existsSync(persistPath)) {
            this._loadPersistedState(persistPath);
        }

        this.initialized = true;

        // Persist initial state
        if (persistPath) {
            this._persistState(persistPath);
        }

        // Start periodic reseed timer
        this._startReseedTimer(persistPath);

        log.info(`PRAHARI v3: Sponge initialized — ${this.sources.size} entropy sources, absorbCount=${this._absorbCount}`);
        return true;
    }

    /**
     * Load persisted sponge state from JSON.
     * Absorbs the old state into current sponge for forward secrecy.
     * Also handles v2 migration: if old file has seeds array, absorb all seeds.
     * @private
     */
    _loadPersistedState(path) {
        try {
            const raw = readFileSync(path, 'utf-8');
            const data = JSON.parse(raw);

            // v3 format: sponge state only
            if (data.spongeState) {
                this._absorb(hexToUint8(data.spongeState), DOMAIN_RESEED);
                log.info('PRAHARI v3: Absorbed persisted sponge state');
            }

            // v2 migration: if old seed array exists, absorb all seeds into sponge
            if (data.seeds && Array.isArray(data.seeds)) {
                log.info(`PRAHARI v3: Migrating v2 pool (${data.seeds.length} slots) → sponge`);
                for (const hex of data.seeds) {
                    if (hex && hex.length >= 64) {
                        this._absorb(hexToUint8(hex), DOMAIN_RESEED);
                    }
                }
                // Save in v3 format immediately
                this._persistState(path);
                log.info('PRAHARI v3: v2→v3 migration complete');
            }

            return true;
        } catch (err) {
            log.warn('Failed to load persisted PRAHARI state: ' + err.message);
            return false;
        }
    }

    /**
     * Persist current sponge state to JSON.
     * Only stores a SHA3 hash of sponge state — not the raw state.
     * @private
     */
    _persistState(path) {
        try {
            const dir = dirname(path);
            if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

            const data = {
                version: 3,
                backend: 'prahari-sponge-v3',
                persistedAt: new Date().toISOString(),
                absorbCount: this._absorbCount,
                // Only persist SHA3 of sponge state — not the raw state
                spongeState: Buffer.from(sha3_256(Buffer.from(this._spongeState))).toString('hex'),
            };

            writeFileSync(path, JSON.stringify(data, null, 2));
            log.trace('PRAHARI v3: Sponge state persisted');
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
     * Reseed — harvest fresh entropy and absorb.
     * Called periodically by the reseed timer.
     * v3: No slot rotation, just absorb fresh entropy into sponge.
     */
    reseed() {
        if (!this.initialized) return;

        // Harvest from all sources
        const sourceCount = this._harvestAndAbsorb();
        if (sourceCount === 0) {
            // No sources available — absorb CSPRNG directly
            this._absorb(randomBytes(32), DOMAIN_RESEED);
        }

        telemetry.reseedCycles++;
        telemetry.lastReseedAt = new Date().toISOString();

        // Persist periodically (every 6 reseeds = ~60 seconds)
        if (this._persistPath && telemetry.reseedCycles % 6 === 0) {
            this._persistState(this._persistPath);
        }

        log.trace(`PRAHARI v3: Reseed #${telemetry.reseedCycles} — absorbed from ${sourceCount} sources`);
    }

    /**
     * Start periodic reseed timer.
     * @private
     */
    _startReseedTimer(persistPath = null) {
        if (this._reseedTimer) clearInterval(this._reseedTimer);
        this._reseedTimer = setInterval(() => this.reseed(), this._reseedIntervalMs);
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
    // HYBRID SEED GENERATION
    // ===================================================================

    /**
     * Get a hybrid seed suitable for ML-KEM-768 keygen.
     * 
     * Algorithm (PRAHARI v3):
     *   1. Squeeze 64 bytes from sponge with domain label "KEYGEN"
     *   2. Generate 64 bytes from OS CSPRNG
     *   3. XOR: hybridSeed = squeezed ⊕ CSPRNG(64)
     * 
     * Security property: Two-source extractor — even if the sponge is fully
     * compromised, CSPRNG ensures the hybrid seed retains entropy.
     * Even if CSPRNG is compromised, the sponge (fed by multiple hardware
     * sources + mesh jitter) ensures entropy.
     * 
     * @returns {Uint8Array} — 64-byte hybrid seed
     */
    getHybridSeed() {
        if (!this.initialized) {
            log.trace('PRAHARI not initialized, falling back to pure CSPRNG');
            return randomBytes(KEYGEN_SEED_BYTES);
        }

        // Squeeze 64 bytes from sponge (domain-separated)
        const squeezed = this._squeeze(KEYGEN_SEED_BYTES, 'PRAHARI-KEYGEN');

        // CSPRNG contribution
        const csprng = randomBytes(KEYGEN_SEED_BYTES);

        // XOR: two-source extractor
        const hybridSeed = new Uint8Array(KEYGEN_SEED_BYTES);
        for (let i = 0; i < KEYGEN_SEED_BYTES; i++) {
            hybridSeed[i] = squeezed[i] ^ csprng[i];
        }

        telemetry.hybridSeeds++;

        log.trace(`Hybrid seed generated (absorbCount=${this._absorbCount}, reseed=${telemetry.reseedCycles})`);
        return hybridSeed;
    }

    /**
     * Squeeze arbitrary-length entropy from the sponge.
     * Domain-separated via label to prevent cross-purpose reuse.
     * Falls back to CSPRNG if sponge is not initialized.
     *
     * @param {number} bytes — number of output bytes
     * @param {string} label — domain separation label (e.g. 'NAKPAK-TIMING', 'SEVA-ID')
     * @returns {Buffer}
     */
    squeeze(bytes, label = 'SQUEEZE') {
        if (!this.initialized) return randomBytes(bytes);
        return Buffer.from(this._squeeze(bytes, label));
    }

    // ===================================================================
    // BACKWARD COMPAT — seedStore API surface
    // ===================================================================

    /** @deprecated v3 has no seeds array — returns empty for compat */
    get seeds() { return []; }

    /** @deprecated v3 has no node assignment */
    get nodeAssignment() { return -1; }

    /**
     * Get status report.
     */
    getStatus() {
        return {
            initialized: this.initialized,
            version: 3,
            absorbCount: this._absorbCount,
            spongeHealthy: this._absorbCount > 0,
            telemetry: { ...telemetry },
            sources: this.sources.getStatus(),
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

/** Global PRAHARI sponge engine (replaces STEADYWATCH seedStore) */
export const seedStore = new PrahariSpongeEngine();

/** Global Entropy Sentinel */
export const sentinel = new EntropySentinel();

/**
 * Initialize PRAHARI v3 subsystem.
 * Drop-in replacement for steadywatch.initialize().
 * 
 * @param {Object} options
 * @param {string} [options.seedFile] — path to persisted sponge state
 * @param {import('../utils/accel.js').InferenceEngine} [options.inferenceEngine] — ACCEL inference
 * @returns {Promise<{ initialized: boolean, sentinel: boolean }>}
 */
export async function initialize(options = {}) {
    const {
        seedFile,
        inferenceEngine = null,
    } = options;

    // Determine persist path
    const persistPath = seedFile || join(__dirname, '../data/prahari-sponge-v3.json');

    // Initialize sponge engine
    seedStore.initialize(persistPath);

    // Initialize Sentinel
    if (inferenceEngine) {
        await sentinel.initialize(inferenceEngine);
    }

    const status = {
        initialized: seedStore.initialized,
        sentinel: sentinel._modelLoaded,
    };

    log.info('PRAHARI v3 initialized:', status);
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
 * Squeeze arbitrary-length entropy from the PRAHARI sponge.
 * Domain-separated — use a unique label per subsystem to prevent cross-purpose reuse.
 * Falls back to CSPRNG if sponge is not initialized.
 *
 * @param {number} bytes — number of output bytes
 * @param {string} label — domain separation label (e.g. 'NAKPAK-TIMING', 'SEVA-ID')
 * @returns {Uint8Array}
 */
export function squeeze(bytes, label) {
    return seedStore.squeeze(bytes, label);
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

export {
    PrahariSpongeEngine,
    PrahariSpongeEngine as PrahariEntropyPool,  // backward compat alias
    PrahariSpongeEngine as SteadywatchSeedStore, // backward compat alias
    EntropySentinel,
    EntropySourceRegistry,
    SourceKind,
    MIN_ENTROPY_RATIO,
};

export default {
    initialize,
    getHybridSeed,
    scoreEntropy,
    getStatus,
    registerEntropySource,
    unregisterEntropySource,
    seedStore,
    sentinel,
};
