/**
 * ACCEL — Adaptive Compute & Crypto Engine Layer
 * 
 * Heterogeneous hardware acceleration for yakmesh data propagation.
 * Routes cryptographic and ML inference operations to the fastest
 * available backend: CPU-SIMD → GPU (CUDA) → NPU (DirectML) → Pure JS.
 * 
 * Architecture:
 *   ┌─────────────────────────────────────────────────┐
 *   │                 accel.js (Scheduler)             │
 *   └───────┬───────────────┬───────────────┬─────────┘
 *           │               │               │
 *    ┌──────┴──────┐ ┌─────┴──────┐ ┌──────┴──────┐
 *    │  CPU-SIMD   │ │  NVIDIA    │ │  AMD NPU    │
 *    │  (OpenSSL/  │ │  (CUDA/    │ │  (ONNX +    │
 *    │   liboqs)   │ │   ONNX)    │ │   DirectML) │
 *    └─────────────┘ └────────────┘ └─────────────┘
 * 
 * Fallback chain: Native addon → GPU batch → Node.js crypto → @noble (pure JS)
 * 
 * Supported hardware:
 *   CPU:  AVX-512, VAES, SHA-NI, GFNI via OpenSSL / liboqs native addon
 *   GPU:  NVIDIA RTX (CUDA) for batch NTT / PQ crypto verification
 *   NPU:  AMD XDNA (DirectML) for ML inference (SAKSHI anomaly, KARMA trust)
 * 
 * @module utils/accel
 * @version 1.0.0
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { createHash, createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { sha3_256 as nobleSha3_256 } from '@noble/hashes/sha3.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { createLogger } from './logger.js';
import os from 'os';
import { execSync } from 'child_process';
import { Worker } from 'worker_threads';
import { fileURLToPath } from 'url';

const log = createLogger('utils:accel');

// =============================================================================
// HARDWARE CAPABILITY FLAGS
// =============================================================================

/**
 * Detected hardware capabilities — populated by probe() at startup.
 * Immutable after initialization.
 */
export const HW = Object.seal({
  // CPU
  cpuModel: '',
  cpuArch: '',
  cores: 0,
  threads: 0,

  // CPU SIMD features (detected via OpenSSL/OS)
  avx512: false,
  vaes: false,
  shaNI: false,
  gfni: false,

  // SHA3 native support (Node.js crypto module via OpenSSL)
  nativeSha3: false,

  // NVIDIA GPU
  nvGpu: false,
  nvGpuName: '',
  nvGpuVRAM: 0,        // MiB
  nvComputeCap: '',     // e.g. '8.6'
  nvCudaVersion: '',    // e.g. '13.1'
  nvDriverVersion: '',
  nvGpuTops: 0,        // INT8 Tensor Core TOPS

  // AMD NPU (XDNA)
  amdNpu: false,
  amdNpuTops: 0,

  // Combined compute budget
  totalTops: 0,        // GPU + NPU combined INT8 TOPS

  // ONNX Runtime availability
  onnxRuntime: false,
  onnxProviders: [],   // ['dml', 'cuda', 'cpu'] — short names per ONNX Runtime 1.24+

  // Native PQ addon (liboqs bindings)
  nativePQ: false,
  nativePQBackend: '',  // 'liboqs' | 'pqcrypto-node' | ''
});

// =============================================================================
// PERFORMANCE TELEMETRY
// =============================================================================

/**
 * Running performance counters for the acceleration layer.
 * Reset per epoch or on demand.
 */
const telemetry = {
  sha3Calls: 0,
  sha3NativeHits: 0,
  signCalls: 0,
  signNativeHits: 0,
  verifyCalls: 0,
  verifyNativeHits: 0,
  batchVerifyCalls: 0,
  batchGpuHits: 0,
  kemCalls: 0,
  kemNativeHits: 0,
  inferCalls: 0,
  inferNpuHits: 0,
  inferGpuHits: 0,
  lastReset: Date.now(),
};

// =============================================================================
// HARDWARE PROBE
// =============================================================================

/**
 * Detect all available hardware acceleration.
 * Call once at startup, before any crypto operations.
 * 
 * @returns {typeof HW} The populated hardware capability flags
 */
export async function probe() {
  const t0 = performance.now();
  log.info('ACCEL probing hardware capabilities...');

  // ---- CPU ----
  const cpus = os.cpus();
  HW.cpuModel = cpus[0]?.model || 'unknown';
  HW.cpuArch = os.arch();
  HW.cores = new Set(cpus.map(c => c.model)).size * (cpus.length / (cpus.length || 1));
  HW.threads = cpus.length;

  // Detect SIMD features from CPU model string + platform heuristics
  _detectCpuFeatures();

  // ---- SHA3 native ----
  HW.nativeSha3 = _probeNativeSha3();

  // ---- NVIDIA GPU ----
  _probeNvidiaGpu();

  // ---- AMD NPU ----
  _probeAmdNpu();

  // ---- ONNX Runtime ----
  await _probeOnnxRuntime();

  // ---- Native PQ addon ----
  _probeNativePQ();

  // ---- Compute combined TOPS budget ----
  HW.totalTops = (HW.nvGpuTops || 0) + (HW.amdNpuTops || 0);

  const elapsed = (performance.now() - t0).toFixed(1);

  // Log capability summary
  const caps = [];
  if (HW.nativeSha3) caps.push('SHA3-native');
  if (HW.avx512) caps.push('AVX-512');
  if (HW.vaes) caps.push('VAES');
  if (HW.shaNI) caps.push('SHA-NI');
  if (HW.gfni) caps.push('GFNI');
  if (HW.nvGpu) caps.push(`GPU:${HW.nvGpuName}(${HW.nvGpuTops}T)`);
  if (HW.amdNpu) caps.push(`NPU:${HW.amdNpuTops}T`);
  if (HW.totalTops > 0) caps.push(`TOTAL:${HW.totalTops}TOPS`);
  if (HW.onnxRuntime) caps.push(`ONNX:[${HW.onnxProviders.join(',')}]`);
  if (HW.nativePQ) caps.push(`PQ:${HW.nativePQBackend}`);

  if (caps.length === 0) {
    caps.push('pure-JS-only');
  }

  log.info(`ACCEL probe complete in ${elapsed}ms — ${caps.join(' | ')}`);

  return HW;
}

/**
 * Detect CPU SIMD features from model string and platform.
 * On x64, Zen 4 / Intel 11th gen+ typically have AVX-512, VAES, SHA-NI, GFNI.
 */
function _detectCpuFeatures() {
  const model = HW.cpuModel.toLowerCase();
  const arch = HW.cpuArch;

  if (arch !== 'x64') return;

  // AMD Zen 4 (Ryzen 7000/8000 series, EPYC Genoa) — has everything
  if (model.includes('ryzen') || model.includes('epyc')) {
    const genMatch = model.match(/(\d{4})/);
    const gen = genMatch ? parseInt(genMatch[1]) : 0;

    // Zen 4 = Ryzen 7000/8000 series, EPYC 9004
    if (gen >= 7000 || (model.includes('epyc') && gen >= 9000)) {
      HW.avx512 = true;
      HW.vaes = true;
      HW.shaNI = true;
      HW.gfni = true;
    } else if (gen >= 3000) {
      // Zen 2+ has SHA-NI
      HW.shaNI = true;
    }
  }

  // Intel — 11th gen+ (Tiger Lake) has AVX-512, VAES, SHA-NI, GFNI
  if (model.includes('core') && model.includes('intel')) {
    const genMatch = model.match(/(\d{2})(\d{2,3})/);
    if (genMatch) {
      const gen = parseInt(genMatch[1]);
      if (gen >= 11) {
        HW.avx512 = true;
        HW.vaes = true;
        HW.shaNI = true;
        HW.gfni = true;
      } else if (gen >= 8) {
        HW.shaNI = true;
      }
    }
  }

  // Server Xeons — Ice Lake+ has AVX-512
  if (model.includes('xeon')) {
    HW.avx512 = true;
    HW.shaNI = true;
    // Conservative: not all Xeons have VAES/GFNI
  }
}

/**
 * Test if Node.js crypto supports SHA3-256 natively (OpenSSL 1.1.1+).
 */
function _probeNativeSha3() {
  try {
    const hash = createHash('sha3-256');
    hash.update(Buffer.from('yakmesh-accel-probe'));
    const digest = hash.digest();
    return digest.length === 32;
  } catch {
    return false;
  }
}

// NVIDIA GPU INT8 Tensor Core TOPS lookup — official NVIDIA specs.
// Maps GPU name substrings → INT8 TOPS rating.
// Sorted longest-match-first within each gen to avoid false partial matches.
const GPU_TOPS_TABLE = [
  // Ada Lovelace (RTX 40-series)
  ['RTX 4090', 1321],
  ['RTX 4080 SUPER', 836],
  ['RTX 4080', 780],
  ['RTX 4070 Ti SUPER', 568],
  ['RTX 4070 Ti', 485],
  ['RTX 4070 SUPER', 418],
  ['RTX 4070', 364],
  ['RTX 4060 Ti', 353],
  ['RTX 4060', 242],
  // Ampere (RTX 30-series)
  ['RTX 3090 Ti', 320],
  ['RTX 3090', 285],
  ['RTX 3080 Ti', 273],
  ['RTX 3080', 238],
  ['RTX 3070 Ti', 174],
  ['RTX 3070', 163],
  ['RTX 3060 Ti', 163],
  ['RTX 3060', 101],
  ['RTX 3050', 73],
  // Turing (RTX 20-series)
  ['RTX 2080 Ti', 215],
  ['RTX 2080 SUPER', 181],
  ['RTX 2080', 161],
  ['RTX 2070 SUPER', 145],
  ['RTX 2070', 130],
  ['RTX 2060 SUPER', 115],
  ['RTX 2060', 104],
  // Workstation
  ['RTX A6000', 310],
  ['RTX A5500', 260],
  ['RTX A5000', 222],
  ['RTX A4500', 180],
  ['RTX A4000', 153],
  // Data center
  ['A100', 624],
  ['H100', 3958],
  ['L40', 362],
];

/**
 * Look up INT8 Tensor Core TOPS for a GPU by name.
 * @param {string} gpuName — full name from nvidia-smi (e.g. 'NVIDIA GeForce RTX 3060')
 * @returns {number} — INT8 TOPS, or 0 if unknown
 */
function _lookupGpuTops(gpuName) {
  const upper = gpuName.toUpperCase();
  for (const [pattern, tops] of GPU_TOPS_TABLE) {
    if (upper.includes(pattern.toUpperCase())) return tops;
  }
  return 0;
}

/**
 * Detect NVIDIA GPU via nvidia-smi.
 */
function _probeNvidiaGpu() {
  if (os.platform() !== 'win32' && os.platform() !== 'linux') return;

  try {
    const output = execSync(
      'nvidia-smi --query-gpu=name,compute_cap,memory.total,driver_version --format=csv,noheader,nounits',
      { timeout: 5000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    ).trim();

    if (!output) return;

    const parts = output.split(',').map(s => s.trim());
    if (parts.length >= 4) {
      HW.nvGpu = true;
      HW.nvGpuName = parts[0];
      HW.nvComputeCap = parts[1];
      HW.nvGpuVRAM = parseInt(parts[2]) || 0;
      HW.nvDriverVersion = parts[3];
      HW.nvGpuTops = _lookupGpuTops(HW.nvGpuName);
      if (HW.nvGpuTops > 0) {
        log.debug(`  GPU TOPS: ${HW.nvGpuName} → ${HW.nvGpuTops} INT8 TOPS`);
      }
    }

    // Get CUDA version separately
    const smiOutput = execSync('nvidia-smi', {
      timeout: 5000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe']
    });
    const cudaMatch = smiOutput.match(/CUDA Version:\s*([\d.]+)/);
    if (cudaMatch) {
      HW.nvCudaVersion = cudaMatch[1];
    }
  } catch {
    // nvidia-smi not available
  }
}

/**
 * Detect AMD XDNA NPU.
 * On Windows, check for AMD IPU Device in Device Manager.
 */
function _probeAmdNpu() {
  if (os.platform() !== 'win32') return;

  try {
    // Check for AMD IPU/NPU device via PowerShell.
    // XDNA registers under multiple PnP classes (System, Processor, SoftwareDevice)
    // so we search ALL classes rather than just 'Processor'.
    const output = execSync(
      'powershell -NoProfile -Command "Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match \'AMD\' -and $_.FriendlyName -match \'IPU|NPU|XDNA|AI\' } | Select-Object -First 1 -ExpandProperty FriendlyName"',
      { timeout: 8000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    ).trim();

    if (output) {
      HW.amdNpu = true;
      log.debug(`  NPU detected (PnP): ${output}`);
      // Assign TOPS rating by CPU model
      const model = HW.cpuModel.toLowerCase();
      if (model.includes('8700') || model.includes('8600')) {
        HW.amdNpuTops = 16;
      } else if (model.includes('7840') || model.includes('7940')) {
        HW.amdNpuTops = 10;
      }
    }
  } catch {
    // PnP query failed — fallback below will handle it
  }

  // Fallback: if PnP didn't detect (empty result or error), check CPU model.
  // The 8700F HAS XDNA NPU — PnP can return empty if driver class doesn't match.
  if (!HW.amdNpu) {
    const model = HW.cpuModel.toLowerCase();
    if (model.includes('8700f') || model.includes('8700g') ||
      model.includes('8600g') || model.includes('8500g') ||
      model.includes('7840') || model.includes('7940') ||
      model.includes('ai 9')) {
      HW.amdNpu = true;
      HW.amdNpuTops = model.includes('8700') || model.includes('8600') ? 16 : 10;
      log.debug(`  NPU detected (model fallback): ${HW.cpuModel} → ${HW.amdNpuTops} TOPS`);
    }
  }
}

/**
 * Probe for ONNX Runtime availability and execution providers.
 */
async function _probeOnnxRuntime() {
  try {
    // Dynamic import — only resolves if onnxruntime-node is installed
    const ort = await import('onnxruntime-node');
    HW.onnxRuntime = true;

    // ONNX Runtime 1.24+ uses listSupportedBackends() with short names
    // Short names: 'cpu', 'dml' (DirectML/NPU), 'cuda', 'webgpu'
    if (typeof ort.listSupportedBackends === 'function') {
      HW.onnxProviders = ort.listSupportedBackends().map(b => b.name);
    } else if (ort.env?.getAvailableProviders) {
      // Legacy ONNX Runtime (<1.20) used long names
      HW.onnxProviders = ort.env.getAvailableProviders();
    } else {
      // Infer from hardware
      const providers = ['cpu'];
      if (HW.nvGpu) providers.unshift('cuda');
      if (HW.amdNpu) providers.unshift('dml');
      HW.onnxProviders = providers;
    }
  } catch {
    // onnxruntime-node not installed
    HW.onnxRuntime = false;
  }
}

/**
 * Probe for native PQ crypto addon (liboqs bindings).
 */
function _probeNativePQ() {
  // Try known packages in priority order
  const candidates = [
    { name: 'liboqs-node', backend: 'liboqs' },
    { name: 'pqcrypto-node', backend: 'pqcrypto' },
    { name: '@aspect/pq-native', backend: 'aspect' },
  ];

  for (const { name, backend } of candidates) {
    try {
      // Synchronous require check (we don't actually load here, just test availability)
      const resolved = import.meta.resolve?.(name);
      if (resolved) {
        HW.nativePQ = true;
        HW.nativePQBackend = backend;
        return;
      }
    } catch {
      // Not available
    }
  }
}

// =============================================================================
// TIER 1: CPU-NATIVE CRYPTO ACCELERATION
// =============================================================================

/**
 * SHA3-256 — accelerated via Node.js native crypto (OpenSSL → SHA-NI).
 * 4.6x faster than @noble/hashes pure JS on Zen 4.
 * 
 * Falls back to @noble/hashes if native SHA3 unavailable.
 * 
 * @param {Uint8Array|Buffer|string} input — data to hash
 * @returns {Uint8Array} — 32-byte SHA3-256 digest
 */
export function sha3_256(input) {
  telemetry.sha3Calls++;

  if (HW.nativeSha3) {
    telemetry.sha3NativeHits++;
    const hash = createHash('sha3-256');

    if (typeof input === 'string') {
      hash.update(input, 'utf8');
    } else {
      hash.update(input);
    }

    // Return Uint8Array for compatibility with @noble/hashes API
    const buf = hash.digest();
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  // Fallback: pure JS
  if (typeof input === 'string') {
    return nobleSha3_256(new TextEncoder().encode(input));
  }
  return nobleSha3_256(input);
}

/**
 * SHA3-256 hex convenience — returns hex string instead of bytes.
 * 
 * @param {Uint8Array|Buffer|string} input
 * @returns {string} — hex-encoded SHA3-256 digest
 */
export function sha3_256hex(input) {
  return bytesToHex(sha3_256(input));
}

// =============================================================================
// TIER 1: ML-DSA-65 (Dilithium3) — Sign / Verify / Keygen
// =============================================================================

// Cache for native PQ module (lazy-loaded)
let _nativePQ = null;

async function _loadNativePQ() {
  if (_nativePQ !== null) return _nativePQ;
  if (!HW.nativePQ) { _nativePQ = false; return false; }

  try {
    switch (HW.nativePQBackend) {
      case 'liboqs': _nativePQ = await import('liboqs-node'); break;
      case 'pqcrypto': _nativePQ = await import('pqcrypto-node'); break;
      case 'aspect': _nativePQ = await import('@aspect/pq-native'); break;
      default: _nativePQ = false;
    }
  } catch {
    _nativePQ = false;
    HW.nativePQ = false;
  }
  return _nativePQ;
}

/**
 * ML-DSA-65 Keygen — generate post-quantum signing keypair.
 * Uses native liboqs (AVX-512 NTT) when available, else @noble pure JS.
 * 
 * @param {Uint8Array} seed — 32-byte seed
 * @returns {{ publicKey: Uint8Array, secretKey: Uint8Array }}
 */
export async function mlDsa65Keygen(seed) {
  const native = await _loadNativePQ();

  if (native && native.ml_dsa65?.keygen) {
    telemetry.signNativeHits++;
    return native.ml_dsa65.keygen(seed);
  }

  return ml_dsa65.keygen(seed);
}

/**
 * ML-DSA-65 Sign — post-quantum digital signature.
 * ~4.9ms pure JS → ~0.5ms with liboqs AVX-512.
 * 
 * @param {Uint8Array} message
 * @param {Uint8Array} secretKey
 * @returns {Uint8Array} signature
 */
export function mlDsa65Sign(message, secretKey) {
  telemetry.signCalls++;

  // Defensive coercion — identity stores keys as hex strings,
  // but @noble/post-quantum expects Uint8Array.  Handle both.
  const sk = typeof secretKey === 'string' ? hexToBytes(secretKey) : secretKey;
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;

  // Synchronous path — native addon is pre-loaded after first call
  if (_nativePQ && _nativePQ.ml_dsa65?.sign) {
    telemetry.signNativeHits++;
    return _nativePQ.ml_dsa65.sign(msg, sk);
  }

  return ml_dsa65.sign(msg, sk);
}

/**
 * ML-DSA-65 Verify — post-quantum signature verification.
 * ~1.7ms pure JS → ~0.2ms with liboqs AVX-512.
 * 
 * @param {Uint8Array} signature
 * @param {Uint8Array} message
 * @param {Uint8Array} publicKey
 * @returns {boolean}
 */
export function mlDsa65Verify(signature, message, publicKey) {
  telemetry.verifyCalls++;

  // Defensive coercion — accept hex strings or Uint8Array for all params
  const sig = typeof signature === 'string' ? hexToBytes(signature) : signature;
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  const pk = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;

  if (_nativePQ && _nativePQ.ml_dsa65?.verify) {
    telemetry.verifyNativeHits++;
    return _nativePQ.ml_dsa65.verify(sig, msg, pk);
  }

  return ml_dsa65.verify(sig, msg, pk);
}

// =============================================================================
// TIER 1: ML-KEM-768 (Kyber) — Key Encapsulation
// =============================================================================

/**
 * ML-KEM-768 Keygen — generate post-quantum KEM keypair.
 * 
 * @param {Uint8Array} seed — 64-byte seed
 * @returns {{ publicKey: Uint8Array, secretKey: Uint8Array }}
 */
export async function mlKem768Keygen(seed) {
  telemetry.kemCalls++;

  const native = await _loadNativePQ();
  if (native && native.ml_kem768?.keygen) {
    telemetry.kemNativeHits++;
    return native.ml_kem768.keygen(seed);
  }

  return ml_kem768.keygen(seed);
}

/**
 * ML-KEM-768 Encapsulate — create shared secret + ciphertext.
 * 
 * @param {Uint8Array} publicKey
 * @returns {{ cipherText: Uint8Array, sharedSecret: Uint8Array }}
 */
export function mlKem768Encapsulate(publicKey) {
  telemetry.kemCalls++;

  // Defensive coercion — accept hex string or Uint8Array
  const pk = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;

  if (_nativePQ && _nativePQ.ml_kem768?.encapsulate) {
    telemetry.kemNativeHits++;
    return _nativePQ.ml_kem768.encapsulate(pk);
  }

  return ml_kem768.encapsulate(pk);
}

/**
 * ML-KEM-768 Decapsulate — recover shared secret from ciphertext.
 * 
 * @param {Uint8Array} cipherText
 * @param {Uint8Array} secretKey
 * @returns {Uint8Array} sharedSecret
 */
export function mlKem768Decapsulate(cipherText, secretKey) {
  telemetry.kemCalls++;

  // Defensive coercion — accept hex string or Uint8Array
  const ct = typeof cipherText === 'string' ? hexToBytes(cipherText) : cipherText;
  const sk = typeof secretKey === 'string' ? hexToBytes(secretKey) : secretKey;

  if (_nativePQ && _nativePQ.ml_kem768?.decapsulate) {
    telemetry.kemNativeHits++;
    return _nativePQ.ml_kem768.decapsulate(ct, sk);
  }

  return ml_kem768.decapsulate(ct, sk);
}

// =============================================================================
// TIER 2: GPU BATCH OPERATIONS
// =============================================================================

/**
 * Batch verification queue.
 * Collects individual verify requests and processes them in batches
 * when queue depth reaches threshold or flush timeout fires.
 * 
 * Acceleration tiers for batch verification:
 * 
 *   1. Worker Thread Pool (CPU-parallel)
 *      Distributes verification chunks across N worker threads
 *      (N = CPU core count). Each worker runs ML-DSA-65 verify in
 *      its own V8 isolate. Achieves near-linear speedup on multi-core
 *      processors. Active on all platforms.
 *      Batch of 256 on Ryzen 8700F (8 cores): ~55ms vs ~435ms sequential.
 * 
 *   2. GPU/CUDA NTT Kernel (future roadmap)
 *      ML-DSA-65 verification's inner loop is NTT (Number Theoretic
 *      Transform) — a prime candidate for GPU SIMD lanes. When CUDA
 *      compute 8.0+ is detected, a precompiled .cubin kernel could
 *      batch all NTT operations into a single GPU dispatch.
 *      Estimated: 256 verifications in <5ms on RTX 4060+.
 *      Blocked on: custom CUDA NTT kernel compilation pipeline.
 * 
 *   3. Sequential CPU fallback
 *      Used when worker pool is unavailable or batch is trivially small.
 *      Calls mlDsa65Verify synchronously per item.
 * 
 * GPU kernel launch overhead (~5-10µs) means batching must clear
 * a minimum queue depth to justify the transfer cost.
 */
class BatchVerifyQueue {
  constructor(options = {}) {
    // Scale batch sizes with available compute TOPS
    // More TOPS → larger batches are worthwhile (GPU can eat them)
    const topsBudget = HW.totalTops || 0;
    this.minBatchSize = options.minBatchSize || (topsBudget >= 100 ? 16 : 8);
    this.maxBatchSize = options.maxBatchSize || (topsBudget >= 200 ? 512 : topsBudget >= 50 ? 256 : 128);
    this.flushInterval = options.flushInterval || 5;  // ms
    this.queue = [];
    this._timer = null;
    this._onnxSession = null;
    this._gpuAvailable = false;

    // Worker thread pool
    this._workers = [];
    this._workerRound = 0;
    this._pendingJobs = new Map();  // jobId → { resolve, reject, batch }
    this._jobCounter = 0;
    this._poolReady = false;
  }

  /**
   * Initialize batch verification subsystem.
   * Creates worker thread pool and checks for GPU availability.
   */
  async initialize() {
    // ---- Worker Thread Pool ----
    // Scale pool size with available compute: more TOPS → more workers
    const basePoolSize = os.cpus().length;
    const topsBoost = HW.totalTops >= 200 ? 2 : (HW.totalTops >= 50 ? 1 : 0);
    const poolSize = Math.max(2, Math.min(basePoolSize + topsBoost, 16));
    const workerPath = new URL('./verify-worker.js', import.meta.url);

    for (let i = 0; i < poolSize; i++) {
      try {
        const w = new Worker(workerPath);

        w.on('message', ({ id, results }) => {
          const job = this._pendingJobs.get(id);
          if (!job) return;
          this._pendingJobs.delete(id);

          // Resolve each individual promise from the original enqueue calls
          for (let j = 0; j < results.length; j++) {
            const { ok, err } = results[j];
            if (err) {
              job.batch[j].reject(new Error(err));
            } else {
              job.batch[j].resolve(ok);
            }
          }
        });

        w.on('error', (err) => {
          log.warn(`Verify worker ${i} error: ${err.message}`);
        });

        this._workers.push(w);
      } catch (err) {
        log.warn(`Failed to spawn verify worker ${i}: ${err.message}`);
      }
    }

    if (this._workers.length > 0) {
      this._poolReady = true;
      log.info(`Batch verify: worker pool ready — ${this._workers.length} threads`);
    } else {
      log.warn('Batch verify: no workers spawned, using sequential CPU');
    }

    // ---- GPU (CUDA) Check ----
    if (HW.onnxRuntime && HW.nvGpu) {
      try {
        const ort = await import('onnxruntime-node');
        const providers = HW.onnxProviders;
        if (providers.includes('cuda')) {
          this._gpuAvailable = true;
          log.info('Batch verify: CUDA provider detected (NTT kernel reserved for future)');
        }
      } catch {
        log.debug('Batch verify: ONNX Runtime not available for GPU path');
      }
    }
  }

  /**
   * Enqueue a verification request.
   * Returns a promise that resolves with the verification result.
   * 
   * @param {Uint8Array} signature
   * @param {Uint8Array} message
   * @param {Uint8Array} publicKey
   * @returns {Promise<boolean>}
   */
  enqueue(signature, message, publicKey) {
    return new Promise((resolve, reject) => {
      this.queue.push({ signature, message, publicKey, resolve, reject });

      if (this.queue.length >= this.minBatchSize) {
        this._flush();
      } else if (!this._timer) {
        this._timer = setTimeout(() => this._flush(), this.flushInterval);
      }
    });
  }

  /**
   * Process all queued verifications.
   * Routes to the fastest available backend:
   *   Worker pool (parallel CPU) → Sequential CPU fallback.
   * 
   * GPU/CUDA NTT batching is detected and telemetry-tracked but
   * currently falls through to worker pool (CUDA kernel TBD).
   */
  _flush() {
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }

    if (this.queue.length === 0) return;

    const batch = this.queue.splice(0, this.maxBatchSize);
    telemetry.batchVerifyCalls++;

    // Track GPU availability hits (CUDA NTT kernel reserved for future)
    if (this._gpuAvailable && batch.length >= this.minBatchSize) {
      telemetry.batchGpuHits++;
      log.trace(`GPU batch verify: ${batch.length} items routed to worker pool (CUDA NTT kernel TBD)`);
    }

    // ---- Worker Thread Pool (true CPU parallelism) ----
    if (this._poolReady && batch.length >= this.minBatchSize) {
      this._dispatchToWorkers(batch);
      return;
    }

    // ---- Sequential CPU fallback (small batches or no workers) ----
    for (const item of batch) {
      try {
        const result = mlDsa65Verify(item.signature, item.message, item.publicKey);
        item.resolve(result);
      } catch (err) {
        item.reject(err);
      }
    }
  }

  /**
   * Distribute a batch across the worker pool for parallel verification.
   * Splits the batch into N chunks (N = worker count) and dispatches
   * each chunk to a worker. Worker results resolve the original promises.
   * 
   * @param {Array} batch — items with { signature, message, publicKey, resolve, reject }
   */
  _dispatchToWorkers(batch) {
    const workerCount = this._workers.length;
    const chunkSize = Math.ceil(batch.length / workerCount);

    for (let i = 0; i < workerCount && i * chunkSize < batch.length; i++) {
      const start = i * chunkSize;
      const end = Math.min(start + chunkSize, batch.length);
      const chunk = batch.slice(start, end);
      const jobId = ++this._jobCounter;

      // Serialize Uint8Arrays for transfer to worker
      const items = chunk.map(item => ({
        signature: item.signature.buffer ? item.signature : new Uint8Array(item.signature),
        message: item.message.buffer ? item.message : new Uint8Array(item.message),
        publicKey: item.publicKey.buffer ? item.publicKey : new Uint8Array(item.publicKey),
      }));

      this._pendingJobs.set(jobId, { batch: chunk });

      const worker = this._workers[i % workerCount];
      worker.postMessage({ id: jobId, items });
    }
  }

  /**
   * Drain queue and stop timer. Terminate worker pool.
   */
  destroy() {
    this._flush();
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    // Terminate worker threads
    for (const w of this._workers) {
      w.terminate().catch(() => { });
    }
    this._workers = [];
    this._poolReady = false;
  }
}

// Singleton batch verifier
export const batchVerify = new BatchVerifyQueue();

// =============================================================================
// TIER 3: NPU INFERENCE ENGINE
// =============================================================================

/**
 * NPU/GPU inference engine for ML models (SAKSHI anomaly, KARMA trust).
 * Uses ONNX Runtime with DirectML (NPU) or CUDA (GPU) providers.
 */
class InferenceEngine {
  constructor() {
    this._sessions = new Map();   // modelName -> InferenceSession
    this._ort = null;
    this._initialized = false;
    this._preferredProvider = null;
  }

  /**
   * Initialize the inference engine.
   * Detects best available provider: DirectML (NPU) > CUDA (GPU) > CPU.
   */
  async initialize() {
    if (this._initialized) return;

    if (!HW.onnxRuntime) {
      log.debug('Inference engine: ONNX Runtime not available');
      this._initialized = true;
      return;
    }

    try {
      this._ort = await import('onnxruntime-node');

      // Provider priority: NPU (DirectML) > GPU (CUDA) > CPU
      // ONNX Runtime 1.24+ uses short names: 'dml', 'cuda', 'cpu'
      const providers = HW.onnxProviders;
      if (providers.includes('dml') && HW.amdNpu) {
        this._preferredProvider = 'dml';
        log.info(`Inference engine: AMD NPU (${HW.amdNpuTops}T) + GPU (${HW.nvGpuTops}T) = ${HW.totalTops}T via DirectML`);
      } else if (providers.includes('cuda') && HW.nvGpu) {
        this._preferredProvider = 'cuda';
        log.info(`Inference engine: NVIDIA GPU (${HW.nvGpuName}, ${HW.nvGpuTops}T) via CUDA`);
      } else if (providers.includes('dml')) {
        this._preferredProvider = 'dml';
        log.info(`Inference engine: DirectML (${HW.totalTops}T available)`);
      } else {
        this._preferredProvider = 'cpu';
        log.info('Inference engine: CPU fallback');
      }

      this._initialized = true;
    } catch (err) {
      log.warn('Inference engine initialization failed:', err.message);
      this._initialized = true;
    }
  }

  /**
   * Load an ONNX model for inference.
   * 
   * @param {string} modelName — unique identifier (e.g., 'sakshi-anomaly')
   * @param {string} modelPath — path to .onnx file
   * @returns {boolean} — true if loaded successfully
   */
  async loadModel(modelName, modelPath) {
    if (!this._ort) {
      log.debug(`Cannot load model ${modelName}: no ONNX Runtime`);
      return false;
    }

    try {
      const options = {};
      if (this._preferredProvider) {
        options.executionProviders = [this._preferredProvider, 'cpu'];
      }

      const session = await this._ort.InferenceSession.create(modelPath, options);
      this._sessions.set(modelName, session);

      log.info(`Model loaded: ${modelName} → ${this._preferredProvider || 'CPU'}`);
      return true;
    } catch (err) {
      log.warn(`Failed to load model ${modelName}: ${err.message}`);
      return false;
    }
  }

  /**
   * Run inference on a loaded model.
   * 
   * @param {string} modelName — which model to run
   * @param {Object<string, Float32Array|Int32Array>} inputs — named input tensors
   * @returns {Object<string, Float32Array>|null} — output tensors, or null if unavailable
   */
  async infer(modelName, inputs) {
    telemetry.inferCalls++;

    const session = this._sessions.get(modelName);
    if (!session) {
      log.trace(`Model ${modelName} not loaded, skipping inference`);
      return null;
    }

    try {
      // Build ONNX tensor feeds
      const feeds = {};
      for (const [name, data] of Object.entries(inputs)) {
        feeds[name] = new this._ort.Tensor('float32', data, [1, data.length]);
      }

      const results = await session.run(feeds);

      // Track NPU/GPU hits
      if (this._preferredProvider === 'dml') {
        telemetry.inferNpuHits++;
      } else if (this._preferredProvider === 'cuda') {
        telemetry.inferGpuHits++;
      }

      // Convert output tensors to plain objects
      const output = {};
      for (const [name, tensor] of Object.entries(results)) {
        output[name] = tensor.data;
      }

      return output;
    } catch (err) {
      log.warn(`Inference failed for ${modelName}: ${err.message}`);
      return null;
    }
  }

  /**
   * Unload a model and free resources.
   */
  async unloadModel(modelName) {
    const session = this._sessions.get(modelName);
    if (session) {
      // ONNX Runtime sessions don't have an explicit close in all versions
      this._sessions.delete(modelName);
      log.debug(`Model unloaded: ${modelName}`);
    }
  }

  /**
   * Check if inference is available for a model.
   */
  hasModel(modelName) {
    return this._sessions.has(modelName);
  }

  /**
   * Check if any hardware acceleration is available.
   */
  get isAccelerated() {
    return this._preferredProvider !== 'cpu' && this._preferredProvider !== null;
  }

  /**
   * Get the active execution provider.
   */
  get provider() {
    return this._preferredProvider || 'none';
  }
}

// Singleton inference engine
export const inference = new InferenceEngine();

// =============================================================================
// TIER 4: HETEROGENEOUS COMPUTE SCHEDULER
// =============================================================================
//
// Routes work to GPU, NPU, or CPU based on task priority, device load,
// queue depth, and (optionally) a trained ONNX scheduling model.
//
// Design principles:
//   1. Every task gets exactly ONE outcome: completed | rejected | timed-out
//   2. Security workloads (CRITICAL) are NEVER dropped
//   3. Bounded queues — no unbounded memory growth under load
//   4. Circuit breakers — a failing device is isolated, not retried blindly
//   5. Work gifting — idle devices pull from busy neighbours
//   6. Self-monitoring — detects own degradation, falls back to rules
//
// Device topology:
//   GPU (cuda/dml)  — high throughput, higher latency, shared w/ display/LLM
//   NPU (dml/xdna)  — low latency, dedicated silicon, always warm
//   CPU (fallback)   — unlimited "TOPS", never refuses, just slower
//

/** Priority classes — higher number = higher priority */
export const Priority = Object.freeze({
  LOW: 0,   // Telemetry, optional analytics — first to shed
  NORMAL: 1,   // SEVA mesh work, planet enhance — rejection allowed
  HIGH: 2,   // Batch verify, trust evaluation — bounded wait
  CRITICAL: 3,   // Entropy sentinel, security checks — NEVER dropped, preempts
});

/** Device identifiers */
export const Device = Object.freeze({
  GPU: 'gpu',
  NPU: 'npu',
  CPU: 'cpu',
});

/** Task affinity hints — what the caller prefers */
export const Affinity = Object.freeze({
  GPU_PREFERRED: 'gpu-preferred',
  NPU_PREFERRED: 'npu-preferred',
  EITHER: 'either',
  CPU_ONLY: 'cpu-only',
});

/** Task outcome states */
const Outcome = Object.freeze({
  COMPLETED: 'completed',
  REJECTED: 'rejected',
  TIMED_OUT: 'timed-out',
  ERROR: 'error',
});

// ---------------------------------------------------------------------------
// CIRCUIT BREAKER — per-device fault isolation
// ---------------------------------------------------------------------------

class CircuitBreaker {
  /**
   * @param {string} deviceName
   * @param {Object} opts
   * @param {number} opts.failThreshold — consecutive failures before opening
   * @param {number} opts.resetMs       — how long the breaker stays open
   * @param {number} opts.probeIntervalMs — interval between probe jobs when open
   */
  constructor(deviceName, opts = {}) {
    this.device = deviceName;
    this.failThreshold = opts.failThreshold || 3;
    this.resetMs = opts.resetMs || 30_000;
    this.probeIntervalMs = opts.probeIntervalMs || 5_000;

    this.state = 'closed';        // closed | open | half-open
    this.consecutiveFailures = 0;
    this.lastFailure = 0;
    this.lastProbe = 0;
    this.totalTrips = 0;          // lifetime trip count
  }

  /** Record a successful execution — resets failure counter */
  recordSuccess() {
    if (this.state === 'half-open') {
      log.info(`Circuit breaker [${this.device}]: CLOSED — probe succeeded`);
      this.state = 'closed';
    }
    this.consecutiveFailures = 0;
  }

  /** Record a failure — may trip the breaker */
  recordFailure() {
    this.consecutiveFailures++;
    this.lastFailure = Date.now();

    if (this.consecutiveFailures >= this.failThreshold && this.state === 'closed') {
      this.state = 'open';
      this.totalTrips++;
      log.warn(`Circuit breaker [${this.device}]: OPEN — ${this.consecutiveFailures} consecutive failures (trip #${this.totalTrips})`);
    }
  }

  /** Can we send work to this device right now? */
  isAvailable() {
    if (this.state === 'closed') return true;
    if (this.state === 'open') {
      // Check if reset period elapsed → transition to half-open
      if (Date.now() - this.lastFailure >= this.resetMs) {
        this.state = 'half-open';
        log.info(`Circuit breaker [${this.device}]: HALF-OPEN — ready for probe`);
        return true; // allow one probe job
      }
      return false;
    }
    // half-open: allow one probe job per interval
    if (Date.now() - this.lastProbe >= this.probeIntervalMs) {
      this.lastProbe = Date.now();
      return true;
    }
    return false;
  }

  getStatus() {
    return {
      device: this.device,
      state: this.state,
      consecutiveFailures: this.consecutiveFailures,
      totalTrips: this.totalTrips,
      lastFailure: this.lastFailure ? new Date(this.lastFailure).toISOString() : null,
    };
  }
}

// ---------------------------------------------------------------------------
// BOUNDED PRIORITY QUEUE — per-device work queue
// ---------------------------------------------------------------------------

class BoundedPriorityQueue {
  /**
   * @param {string} deviceName
   * @param {number} capacity — max items (derived from device TOPS)
   */
  constructor(deviceName, capacity) {
    this.device = deviceName;
    this.capacity = capacity;
    this._queues = {
      [Priority.CRITICAL]: [],
      [Priority.HIGH]: [],
      [Priority.NORMAL]: [],
      [Priority.LOW]: [],
    };
    this._size = 0;
    this._totalEnqueued = 0;
    this._totalDropped = 0;
    this._totalCompleted = 0;
  }

  /** Current queue depth */
  get size() { return this._size; }

  /** Load factor 0.0-1.0 */
  get loadFactor() { return this._size / this.capacity; }

  /**
   * Enqueue a task. Returns true if accepted, false if rejected.
   * CRITICAL tasks can preempt LOW tasks when full.
   */
  enqueue(task) {
    // Always accept CRITICAL
    if (task.priority === Priority.CRITICAL) {
      // If full, shed a LOW task to make room
      if (this._size >= this.capacity) {
        const shed = this._queues[Priority.LOW].shift();
        if (shed) {
          this._size--;
          this._totalDropped++;
          shed.reject({ outcome: Outcome.REJECTED, reason: 'shed-for-critical', device: this.device });
          log.debug(`Scheduler [${this.device}]: shed LOW task ${shed.id} to admit CRITICAL ${task.id}`);
        }
        // If still full after shedding, enqueue anyway (CRITICAL never refused)
      }
      this._queues[Priority.CRITICAL].push(task);
      this._size++;
      this._totalEnqueued++;
      return true;
    }

    // Non-critical: reject if full
    if (this._size >= this.capacity) {
      this._totalDropped++;
      return false;
    }

    this._queues[task.priority].push(task);
    this._size++;
    this._totalEnqueued++;
    return true;
  }

  /**
   * Dequeue the highest-priority task.
   * Returns null if empty.
   */
  dequeue() {
    for (const p of [Priority.CRITICAL, Priority.HIGH, Priority.NORMAL, Priority.LOW]) {
      if (this._queues[p].length > 0) {
        this._size--;
        return this._queues[p].shift();
      }
    }
    return null;
  }

  /**
   * Peek at next task without removing.
   */
  peek() {
    for (const p of [Priority.CRITICAL, Priority.HIGH, Priority.NORMAL, Priority.LOW]) {
      if (this._queues[p].length > 0) return this._queues[p][0];
    }
    return null;
  }

  /**
   * Gift a LOW or NORMAL task for work-gifting.
   * Returns null if nothing giftable.
   */
  gift() {
    for (const p of [Priority.LOW, Priority.NORMAL]) {
      if (this._queues[p].length > 0) {
        this._size--;
        return this._queues[p].shift();
      }
    }
    return null;
  }

  /**
   * Drain all pending tasks (returns array). Used during shutdown.
   */
  drain() {
    const all = [];
    for (const p of [Priority.CRITICAL, Priority.HIGH, Priority.NORMAL, Priority.LOW]) {
      all.push(...this._queues[p].splice(0));
    }
    this._size = 0;
    return all;
  }

  getStatus() {
    return {
      device: this.device,
      capacity: this.capacity,
      depth: this._size,
      loadFactor: +(this.loadFactor.toFixed(2)),
      byPriority: {
        critical: this._queues[Priority.CRITICAL].length,
        high: this._queues[Priority.HIGH].length,
        normal: this._queues[Priority.NORMAL].length,
        low: this._queues[Priority.LOW].length,
      },
      lifetime: {
        enqueued: this._totalEnqueued,
        dropped: this._totalDropped,
        completed: this._totalCompleted,
      },
    };
  }
}

// ---------------------------------------------------------------------------
// TRAINING DATA LOGGER — records execution history for scheduler model
// ---------------------------------------------------------------------------

class TrainingDataLogger {
  constructor(maxEntries = 10_000) {
    this._entries = [];
    this._maxEntries = maxEntries;
    this._flushCallbacks = [];
  }

  /**
   * Record a completed task's execution data.
   * This is pure gold — every entry trains the future scheduler model.
   */
  record(entry) {
    this._entries.push({
      ts: Date.now(),
      taskType: entry.taskType,
      priority: entry.priority,
      affinity: entry.affinity,
      device: entry.device,
      inputSize: entry.inputSize || 0,
      queueDepthAtSubmit: entry.queueDepthAtSubmit || 0,
      gpuLoadAtSubmit: entry.gpuLoadAtSubmit || 0,
      npuLoadAtSubmit: entry.npuLoadAtSubmit || 0,
      cpuLoadAtSubmit: entry.cpuLoadAtSubmit || 0,
      waitMs: entry.waitMs || 0,
      execMs: entry.execMs || 0,
      outcome: entry.outcome,
      success: entry.outcome === Outcome.COMPLETED,
    });

    // Ring buffer — drop oldest when full
    if (this._entries.length > this._maxEntries) {
      this._entries.shift();
    }
  }

  /**
   * Get recent entries for model training.
   * @param {number} n — max entries to return
   */
  getRecent(n = 1000) {
    return this._entries.slice(-n);
  }

  /**
   * Build a feature vector from current scheduler state for ML inference.
   * This is what the ONNX scheduler model consumes.
   *
   * @param {Object} task — incoming task descriptor
   * @param {Object} state — current scheduler state snapshot
   * @returns {Float32Array} — input vector for scheduler model
   */
  buildFeatureVector(task, state) {
    return new Float32Array([
      task.taskTypeId || 0,              // 0: task type enum
      task.inputSize || 0,               // 1: input payload size
      task.priority || 0,                // 2: priority class
      state.gpuQueueDepth || 0,          // 3: GPU queue depth
      state.npuQueueDepth || 0,          // 4: NPU queue depth
      state.cpuQueueDepth || 0,          // 5: CPU queue depth
      state.gpuActiveJobs || 0,          // 6: GPU in-flight
      state.npuActiveJobs || 0,          // 7: NPU in-flight
      state.cpuActiveJobs || 0,          // 8: CPU in-flight
      state.gpuAvgLatency || 0,          // 9: GPU recent avg latency (ms)
      state.npuAvgLatency || 0,          // 10: NPU recent avg latency (ms)
      state.cpuAvgLatency || 0,          // 11: CPU recent avg latency (ms)
      state.gpuLoadFactor || 0,          // 12: GPU queue fill ratio 0-1
      state.npuLoadFactor || 0,          // 13: NPU queue fill ratio 0-1
      state.burstRate10ms || 0,          // 14: tasks in last 10ms
      state.burstRate100ms || 0,         // 15: tasks in last 100ms
      state.gpuCircuitOpen ? 1 : 0,     // 16: GPU circuit breaker state
      state.npuCircuitOpen ? 1 : 0,     // 17: NPU circuit breaker state
      state.gpuTops || 0,               // 18: GPU TOPS rating
      state.npuTops || 0,               // 19: NPU TOPS rating
    ]);
  }

  /** Entry count */
  get size() { return this._entries.length; }

  getStatus() {
    return {
      entries: this._entries.length,
      maxEntries: this._maxEntries,
      oldestTs: this._entries.length > 0 ? new Date(this._entries[0].ts).toISOString() : null,
      newestTs: this._entries.length > 0 ? new Date(this._entries[this._entries.length - 1].ts).toISOString() : null,
    };
  }
}

// ---------------------------------------------------------------------------
// COMPUTE SCHEDULER — the brain
// ---------------------------------------------------------------------------

/**
 * ComputeScheduler — heterogeneous GPU/NPU/CPU work router.
 *
 * Submit a task with a type, priority, affinity hint, and executor function.
 * The scheduler decides which device runs it, manages queues, circuit breakers,
 * timeouts, and work gifting. Optionally uses a trained ONNX model for routing.
 */
class ComputeScheduler {
  constructor() {
    // Per-device state
    this._queues = {};       // device → BoundedPriorityQueue
    this._breakers = {};     // device → CircuitBreaker
    this._activeJobs = {};   // device → Set<taskId>
    this._avgLatency = {};   // device → running average (ms)

    // Task tracking
    this._taskCounter = 0;
    this._pendingTasks = new Map();  // taskId → { task, resolve, reject, timer }

    // ML routing model (optional — loaded via loadSchedulerModel)
    this._schedulerSession = null;
    this._useMLRouting = false;
    this._mlAccuracy = 1.0;   // self-monitored accuracy — degrades → fallback to rules

    // Training data
    this._trainingLog = new TrainingDataLogger(10_000);

    // Burst rate tracking (sliding window)
    this._recentSubmits = [];  // timestamps of recent submits

    // Work-gifting interval
    this._giftTimer = null;

    // Lifecycle
    this._initialized = false;
    this._shutdownRequested = false;

    // Stats
    this._stats = {
      totalSubmitted: 0,
      totalCompleted: 0,
      totalRejected: 0,
      totalTimedOut: 0,
      totalErrors: 0,
      totalGifted: 0,
      mlRoutingDecisions: 0,
      ruleRoutingDecisions: 0,
    };
  }

  /**
   * Initialize the scheduler. Must be called after probe().
   * Sets up queues and breakers based on detected hardware.
   */
  async initialize() {
    if (this._initialized) return;

    // GPU queue — capacity scaled from TOPS
    const gpuTops = HW.nvGpuTops || 0;
    const npuTops = HW.amdNpuTops || 0;

    const gpuCapacity = gpuTops > 0 ? Math.max(32, Math.ceil(gpuTops * 2)) : 0;
    const npuCapacity = npuTops > 0 ? Math.max(16, Math.ceil(npuTops * 2)) : 0;
    const cpuCapacity = Math.max(64, HW.threads * 4);

    // Create queues for available devices
    if (gpuTops > 0 && HW.nvGpu) {
      this._queues[Device.GPU] = new BoundedPriorityQueue(Device.GPU, gpuCapacity);
      this._breakers[Device.GPU] = new CircuitBreaker(Device.GPU);
      this._activeJobs[Device.GPU] = new Set();
      this._avgLatency[Device.GPU] = 0;
      log.info(`Scheduler: GPU queue initialized — capacity ${gpuCapacity} (${gpuTops}T)`);
    }

    if (npuTops > 0 && HW.amdNpu) {
      this._queues[Device.NPU] = new BoundedPriorityQueue(Device.NPU, npuCapacity);
      this._breakers[Device.NPU] = new CircuitBreaker(Device.NPU);
      this._activeJobs[Device.NPU] = new Set();
      this._avgLatency[Device.NPU] = 0;
      log.info(`Scheduler: NPU queue initialized — capacity ${npuCapacity} (${npuTops}T)`);
    }

    // CPU always available
    this._queues[Device.CPU] = new BoundedPriorityQueue(Device.CPU, cpuCapacity);
    this._breakers[Device.CPU] = new CircuitBreaker(Device.CPU, { failThreshold: 10 }); // CPU is resilient
    this._activeJobs[Device.CPU] = new Set();
    this._avgLatency[Device.CPU] = 0;
    log.info(`Scheduler: CPU queue initialized — capacity ${cpuCapacity} (${HW.threads} threads)`);

    // Start work-gifting loop (checks every 50ms)
    this._giftTimer = setInterval(() => this._workGift(), 50);
    if (this._giftTimer.unref) this._giftTimer.unref();

    this._initialized = true;

    const devices = Object.keys(this._queues);
    const totalCapacity = Object.values(this._queues).reduce((s, q) => s + q.capacity, 0);
    log.info(`Scheduler: ready — ${devices.length} devices, ${totalCapacity} total queue slots, ${HW.totalTops}T combined`);
  }

  // =========================================================================
  // ML SCHEDULER MODEL
  // =========================================================================

  /**
   * Load a trained ONNX scheduling model.
   * Input: 20-float feature vector (see TrainingDataLogger.buildFeatureVector)
   * Output: [device_id, expected_ms, should_split, split_ratio]
   *
   * @param {string} modelPath — path to scheduler.onnx
   */
  async loadSchedulerModel(modelPath) {
    if (!HW.onnxRuntime) {
      log.debug('Scheduler: cannot load ML model — no ONNX Runtime');
      return false;
    }
    try {
      const ort = await import('onnxruntime-node');
      const cpuProv = HW.onnxProviders.find(p => p.toLowerCase().includes('cpu')) || 'cpu';
      // Scheduler model always runs on NPU (tiny, low-latency) or CPU
      const dmlProv = HW.onnxProviders.find(p => p.toLowerCase().includes('dml'));
      const providers = dmlProv ? [dmlProv, cpuProv] : [cpuProv];

      this._schedulerSession = await ort.InferenceSession.create(modelPath, {
        executionProviders: providers,
      });
      this._useMLRouting = true;
      this._ort = ort;
      log.info(`Scheduler: ML routing model loaded from ${modelPath}`);
      return true;
    } catch (err) {
      log.warn(`Scheduler: failed to load ML model: ${err.message}`);
      return false;
    }
  }

  /**
   * Query the ML model for a routing decision.
   * Falls back to rules if model unavailable or degraded.
   *
   * @param {Object} task
   * @returns {{ device: string, expectedMs: number, shouldSplit: boolean, splitRatio: number }}
   */
  async _mlRoute(task) {
    if (!this._useMLRouting || !this._schedulerSession || this._mlAccuracy < 0.5) {
      return null; // ML unavailable or degraded — use rules
    }

    try {
      const state = this._getStateSnapshot();
      const features = this._trainingLog.buildFeatureVector(task, state);
      const inputTensor = new this._ort.Tensor('float32', features, [1, features.length]);
      const results = await this._schedulerSession.run({ input: inputTensor });
      const output = results.output?.data || results[Object.keys(results)[0]]?.data;

      if (!output || output.length < 4) return null;

      const deviceMap = { 0: Device.GPU, 1: Device.NPU, 2: Device.CPU };
      const deviceId = Math.round(output[0]);

      this._stats.mlRoutingDecisions++;

      return {
        device: deviceMap[deviceId] || Device.CPU,
        expectedMs: output[1],
        shouldSplit: output[2] > 0.5,
        splitRatio: Math.max(0, Math.min(1, output[3])),
      };
    } catch {
      // Model inference failed — degrade gracefully
      this._mlAccuracy *= 0.9;
      if (this._mlAccuracy < 0.5) {
        log.warn('Scheduler: ML accuracy degraded below 50% — falling back to rule-based routing');
      }
      return null;
    }
  }

  // =========================================================================
  // RULE-BASED ROUTING (fallback & default)
  // =========================================================================

  /**
   * Determine the best device for a task using rules.
   * Considers: affinity hint, circuit breaker state, queue load, priority.
   */
  _ruleRoute(task) {
    const available = {};
    for (const [dev, breaker] of Object.entries(this._breakers)) {
      if (breaker.isAvailable()) {
        available[dev] = {
          load: this._queues[dev].loadFactor,
          active: this._activeJobs[dev].size,
          latency: this._avgLatency[dev],
        };
      }
    }

    this._stats.ruleRoutingDecisions++;

    // CPU-only affinity
    if (task.affinity === Affinity.CPU_ONLY) {
      return Device.CPU;
    }

    // CRITICAL always goes to the least-loaded available accelerator
    if (task.priority === Priority.CRITICAL) {
      if (available[Device.NPU] && available[Device.NPU].load < 0.95) return Device.NPU;
      if (available[Device.GPU] && available[Device.GPU].load < 0.95) return Device.GPU;
      return Device.CPU; // CPU never refuses CRITICAL
    }

    // Affinity-preferred routing with load-aware fallback
    if (task.affinity === Affinity.GPU_PREFERRED && available[Device.GPU]) {
      if (available[Device.GPU].load < 0.8) return Device.GPU;
      // GPU busy — can NPU help?
      if (available[Device.NPU] && available[Device.NPU].load < 0.6) return Device.NPU;
      // Both busy — still try GPU if not at wall
      if (available[Device.GPU].load < 0.95) return Device.GPU;
      return Device.CPU;
    }

    if (task.affinity === Affinity.NPU_PREFERRED && available[Device.NPU]) {
      if (available[Device.NPU].load < 0.8) return Device.NPU;
      if (available[Device.GPU] && available[Device.GPU].load < 0.6) return Device.GPU;
      if (available[Device.NPU].load < 0.95) return Device.NPU;
      return Device.CPU;
    }

    // EITHER affinity — pick the least loaded accelerator
    if (available[Device.NPU] && available[Device.GPU]) {
      // NPU is lower-latency for small tasks, GPU for large
      const npuBetter = available[Device.NPU].load < available[Device.GPU].load;
      const preferred = npuBetter ? Device.NPU : Device.GPU;
      const fallback = npuBetter ? Device.GPU : Device.NPU;
      if (available[preferred].load < 0.8) return preferred;
      if (available[fallback].load < 0.8) return fallback;
      return Device.CPU;
    }

    if (available[Device.NPU]) return available[Device.NPU].load < 0.9 ? Device.NPU : Device.CPU;
    if (available[Device.GPU]) return available[Device.GPU].load < 0.9 ? Device.GPU : Device.CPU;

    return Device.CPU;
  }

  // =========================================================================
  // TASK SUBMISSION
  // =========================================================================

  /**
   * Submit a task to the compute scheduler.
   *
   * @param {Object} descriptor — task descriptor
   * @param {string} descriptor.type     — task type name (e.g. 'entropy-sentinel', 'batch-verify')
   * @param {number} descriptor.typeId   — numeric type ID for ML model (optional)
   * @param {number} descriptor.priority — Priority.CRITICAL | HIGH | NORMAL | LOW
   * @param {string} descriptor.affinity — Affinity.GPU_PREFERRED | NPU_PREFERRED | EITHER | CPU_ONLY
   * @param {number} descriptor.timeoutMs — max allowed execution time (0 = no timeout)
   * @param {number} descriptor.inputSize — rough input payload size (for ML features)
   * @param {Object} descriptor.executors — { gpu: fn, npu: fn, cpu: fn } — at least cpu required
   * @returns {Promise<{ outcome, device, result, execMs, waitMs }>}
   */
  submit(descriptor) {
    if (this._shutdownRequested) {
      return Promise.reject({ outcome: Outcome.REJECTED, reason: 'scheduler-shutting-down' });
    }

    const taskId = ++this._taskCounter;
    const submitTime = performance.now();
    this._stats.totalSubmitted++;

    // Track burst rate
    this._recentSubmits.push(submitTime);
    // Prune old entries (keep last 200ms)
    const cutoff = submitTime - 200;
    while (this._recentSubmits.length > 0 && this._recentSubmits[0] < cutoff) {
      this._recentSubmits.shift();
    }

    return new Promise(async (resolve, reject) => {
      const task = {
        id: taskId,
        type: descriptor.type || 'unknown',
        taskTypeId: descriptor.typeId || 0,
        priority: descriptor.priority ?? Priority.NORMAL,
        affinity: descriptor.affinity || Affinity.EITHER,
        timeoutMs: descriptor.timeoutMs || 5000,
        inputSize: descriptor.inputSize || 0,
        executors: descriptor.executors || {},
        submitTime,
        resolve,
        reject,
        timer: null,
      };

      // Route decision: ML model first, fall back to rules
      let targetDevice;
      const mlDecision = await this._mlRoute(task);
      if (mlDecision) {
        targetDevice = mlDecision.device;
        task._mlExpectedMs = mlDecision.expectedMs;
      } else {
        targetDevice = this._ruleRoute(task);
      }

      // Ensure target device has an executor; fall back through chain
      if (!task.executors[targetDevice]) {
        if (targetDevice === Device.GPU && task.executors[Device.NPU]) targetDevice = Device.NPU;
        else if (targetDevice === Device.NPU && task.executors[Device.GPU]) targetDevice = Device.GPU;
        else targetDevice = Device.CPU;
      }

      // Final check: must have an executor for the chosen device
      if (!task.executors[targetDevice]) {
        this._stats.totalRejected++;
        reject({ outcome: Outcome.REJECTED, reason: `no-executor-for-${targetDevice}`, taskId });
        return;
      }

      task.targetDevice = targetDevice;

      // Enqueue
      const queue = this._queues[targetDevice];
      if (!queue) {
        // Device not available — retry on CPU
        task.targetDevice = Device.CPU;
        const cpuQueue = this._queues[Device.CPU];
        if (!cpuQueue.enqueue(task)) {
          this._stats.totalRejected++;
          reject({
            outcome: Outcome.REJECTED,
            reason: 'all-queues-full',
            taskId,
            retryAfterMs: 100,
          });
          return;
        }
      } else {
        const accepted = queue.enqueue(task);
        if (!accepted) {
          // Try CPU spillover
          if (targetDevice !== Device.CPU && this._queues[Device.CPU]) {
            task.targetDevice = Device.CPU;
            if (!task.executors[Device.CPU]) {
              this._stats.totalRejected++;
              reject({
                outcome: Outcome.REJECTED,
                reason: `${targetDevice}-queue-full-no-cpu-executor`,
                taskId,
                retryAfterMs: 200,
              });
              return;
            }
            const cpuAccepted = this._queues[Device.CPU].enqueue(task);
            if (!cpuAccepted) {
              this._stats.totalRejected++;
              reject({
                outcome: Outcome.REJECTED,
                reason: 'all-queues-full',
                taskId,
                retryAfterMs: 500,
              });
              return;
            }
          } else {
            this._stats.totalRejected++;
            reject({
              outcome: Outcome.REJECTED,
              reason: `${targetDevice}-queue-full`,
              taskId,
              retryAfterMs: 200,
            });
            return;
          }
        }
      }

      // Set timeout
      if (task.timeoutMs > 0) {
        task.timer = setTimeout(() => {
          if (this._pendingTasks.has(taskId)) {
            this._pendingTasks.delete(taskId);
            this._stats.totalTimedOut++;
            reject({ outcome: Outcome.TIMED_OUT, taskId, device: task.targetDevice, timeoutMs: task.timeoutMs });
          }
        }, task.timeoutMs);
        if (task.timer.unref) task.timer.unref();
      }

      this._pendingTasks.set(taskId, task);

      // Kick the processor for this device
      this._processQueue(task.targetDevice);
    });
  }

  // =========================================================================
  // QUEUE PROCESSING — execute tasks from a device queue
  // =========================================================================

  /**
   * Process pending tasks on a device.
   * Runs concurrently up to device capacity.
   */
  async _processQueue(device) {
    const queue = this._queues[device];
    const breaker = this._breakers[device];
    const active = this._activeJobs[device];
    if (!queue || !breaker || !active) return;

    // Max concurrent jobs per device
    const maxConcurrent = device === Device.GPU
      ? Math.max(4, Math.ceil((HW.nvGpuTops || 1) / 10))
      : device === Device.NPU
        ? Math.max(2, Math.ceil((HW.amdNpuTops || 1) / 4))
        : HW.threads || 4;

    while (queue.size > 0 && active.size < maxConcurrent) {
      if (!breaker.isAvailable()) break;

      const task = queue.dequeue();
      if (!task) break;
      if (!this._pendingTasks.has(task.id)) continue; // already timed out

      active.add(task.id);
      const execStart = performance.now();

      // Execute asynchronously
      this._executeTask(task, device, execStart).catch(() => { });
    }
  }

  /**
   * Execute a single task on a device.
   */
  async _executeTask(task, device, execStart) {
    const executor = task.executors[device];
    const breaker = this._breakers[device];
    const active = this._activeJobs[device];
    const queue = this._queues[device];

    try {
      const result = await executor();
      const execMs = performance.now() - execStart;
      const waitMs = execStart - task.submitTime;

      // Clear timeout
      if (task.timer) clearTimeout(task.timer);

      // Remove from tracking
      this._pendingTasks.delete(task.id);
      active.delete(task.id);
      if (queue) queue._totalCompleted++;

      // Record success
      breaker.recordSuccess();
      this._updateAvgLatency(device, execMs);
      this._stats.totalCompleted++;

      // Log training data
      this._trainingLog.record({
        taskType: task.type,
        priority: task.priority,
        affinity: task.affinity,
        device,
        inputSize: task.inputSize,
        queueDepthAtSubmit: queue ? queue.size : 0,
        gpuLoadAtSubmit: this._queues[Device.GPU]?.loadFactor || 0,
        npuLoadAtSubmit: this._queues[Device.NPU]?.loadFactor || 0,
        cpuLoadAtSubmit: this._queues[Device.CPU]?.loadFactor || 0,
        waitMs,
        execMs,
        outcome: Outcome.COMPLETED,
      });

      // ML accuracy self-check
      if (task._mlExpectedMs && execMs > 0) {
        const ratio = execMs / task._mlExpectedMs;
        if (ratio > 3 || ratio < 0.1) {
          this._mlAccuracy *= 0.95; // penalize bad predictions
        } else {
          this._mlAccuracy = Math.min(1.0, this._mlAccuracy * 1.01); // reward good ones
        }
      }

      // Resolve the promise
      task.resolve({
        outcome: Outcome.COMPLETED,
        device,
        result,
        execMs: +execMs.toFixed(2),
        waitMs: +waitMs.toFixed(2),
        taskId: task.id,
      });
    } catch (err) {
      const execMs = performance.now() - execStart;
      if (task.timer) clearTimeout(task.timer);
      this._pendingTasks.delete(task.id);
      active.delete(task.id);

      breaker.recordFailure();
      this._stats.totalErrors++;

      // Log failure for training
      this._trainingLog.record({
        taskType: task.type,
        priority: task.priority,
        affinity: task.affinity,
        device,
        inputSize: task.inputSize,
        queueDepthAtSubmit: 0,
        gpuLoadAtSubmit: 0,
        npuLoadAtSubmit: 0,
        cpuLoadAtSubmit: 0,
        waitMs: execStart - task.submitTime,
        execMs,
        outcome: Outcome.ERROR,
      });

      // AUTO-RESCUE: If a non-CPU device fails and CPU executor exists, retry on CPU
      if (device !== Device.CPU && task.executors[Device.CPU]) {
        log.debug(`Scheduler: ${device} failed for task ${task.id} (${task.type}), retrying on CPU`);
        try {
          const cpuStart = performance.now();
          const result = await task.executors[Device.CPU]();
          const cpuExecMs = performance.now() - cpuStart;

          this._stats.totalCompleted++;
          this._breakers[Device.CPU].recordSuccess();

          task.resolve({
            outcome: Outcome.COMPLETED,
            device: Device.CPU,
            result,
            execMs: +cpuExecMs.toFixed(2),
            waitMs: +(cpuStart - task.submitTime).toFixed(2),
            taskId: task.id,
            rescue: true,  // indicates this was a CPU rescue
          });
          return;
        } catch (cpuErr) {
          // Even CPU failed — truly broken task
          log.warn(`Scheduler: CPU rescue also failed for task ${task.id}: ${cpuErr.message}`);
        }
      }

      task.reject({
        outcome: Outcome.ERROR,
        device,
        error: err.message,
        taskId: task.id,
        execMs: +execMs.toFixed(2),
      });
    } finally {
      // Always try to process more from this device's queue
      setImmediate(() => this._processQueue(device));
    }
  }

  // =========================================================================
  // WORK GIFTING — idle devices pull from busy neighbours
  // =========================================================================

  _workGift() {
    if (this._shutdownRequested) return;

    for (const [device, active] of Object.entries(this._activeJobs)) {
      const queue = this._queues[device];
      const breaker = this._breakers[device];
      if (!queue || !breaker || !breaker.isAvailable()) continue;

      // Is this device idle?
      const maxConcurrent = device === Device.GPU
        ? Math.max(4, Math.ceil((HW.nvGpuTops || 1) / 10))
        : device === Device.NPU
          ? Math.max(2, Math.ceil((HW.amdNpuTops || 1) / 4))
          : HW.threads || 4;

      if (active.size >= maxConcurrent * 0.5) continue; // not idle enough
      if (queue.size > 0) continue; // has own work to do

      // Find the busiest other queue and gift from it
      let busiestDevice = null;
      let busiestLoad = 0;
      for (const [otherDev, otherQueue] of Object.entries(this._queues)) {
        if (otherDev === device) continue;
        if (otherQueue.loadFactor > busiestLoad && otherQueue.size > 1) {
          busiestLoad = otherQueue.loadFactor;
          busiestDevice = otherDev;
        }
      }

      if (busiestDevice && busiestLoad > 0.3) {
        const gifted = this._queues[busiestDevice].gift();
        if (gifted && gifted.executors[device]) {
          // Re-target to receiving device
          gifted.targetDevice = device;
          this._queues[device].enqueue(gifted);
          this._stats.totalGifted++;
          log.trace(`Scheduler: ${busiestDevice} gifted ${gifted.type} task ${gifted.id} to ${device}`);
          this._processQueue(device);
        } else if (gifted) {
          // Can't execute on this device — put it back
          this._queues[busiestDevice].enqueue(gifted);
        }
      }
    }
  }

  // =========================================================================
  // STATE & TELEMETRY
  // =========================================================================

  /** Update exponential moving average latency for a device */
  _updateAvgLatency(device, ms) {
    const alpha = 0.1; // smoothing factor
    this._avgLatency[device] = this._avgLatency[device] * (1 - alpha) + ms * alpha;
  }

  /** Get burst rate (tasks submitted in last N ms) */
  _getBurstRate(windowMs) {
    const cutoff = performance.now() - windowMs;
    return this._recentSubmits.filter(t => t >= cutoff).length;
  }

  /** Snapshot of current scheduler state (for ML model or status) */
  _getStateSnapshot() {
    return {
      gpuQueueDepth: this._queues[Device.GPU]?.size || 0,
      npuQueueDepth: this._queues[Device.NPU]?.size || 0,
      cpuQueueDepth: this._queues[Device.CPU]?.size || 0,
      gpuActiveJobs: this._activeJobs[Device.GPU]?.size || 0,
      npuActiveJobs: this._activeJobs[Device.NPU]?.size || 0,
      cpuActiveJobs: this._activeJobs[Device.CPU]?.size || 0,
      gpuAvgLatency: this._avgLatency[Device.GPU] || 0,
      npuAvgLatency: this._avgLatency[Device.NPU] || 0,
      cpuAvgLatency: this._avgLatency[Device.CPU] || 0,
      gpuLoadFactor: this._queues[Device.GPU]?.loadFactor || 0,
      npuLoadFactor: this._queues[Device.NPU]?.loadFactor || 0,
      gpuCircuitOpen: this._breakers[Device.GPU]?.state === 'open',
      npuCircuitOpen: this._breakers[Device.NPU]?.state === 'open',
      burstRate10ms: this._getBurstRate(10),
      burstRate100ms: this._getBurstRate(100),
      gpuTops: HW.nvGpuTops || 0,
      npuTops: HW.amdNpuTops || 0,
    };
  }

  // =========================================================================
  // ADVISORY ROUTING (for cross-process pipe clients)
  // =========================================================================

  /**
   * Get a routing recommendation without enqueuing a task.
   * Used by c2c/yakai via named pipe to decide which device to run on.
   * Does NOT consume queue capacity — purely advisory.
   *
   * @param {Object} descriptor
   * @param {string} descriptor.type     — task type name
   * @param {number} descriptor.priority — Priority value
   * @param {string} descriptor.affinity — Affinity value
   * @param {number} [descriptor.inputSize] — rough input payload size
   * @returns {Promise<{ device: string, queueLoad: Object, method: string }>}
   */
  async advise(descriptor) {
    const task = {
      id: 0,
      type: descriptor.type || 'advisory',
      taskTypeId: descriptor.typeId || 0,
      priority: descriptor.priority ?? Priority.NORMAL,
      affinity: descriptor.affinity || Affinity.EITHER,
      inputSize: descriptor.inputSize || 0,
    };

    // Try ML routing first, fall back to rules (same logic as submit)
    let device, method;
    const mlDecision = await this._mlRoute(task);
    if (mlDecision) {
      device = mlDecision.device;
      method = 'ml';
    } else {
      device = this._ruleRoute(task);
      method = 'rules';
    }

    return {
      device,
      method,
      queueLoad: {
        gpu: +(this._queues[Device.GPU]?.loadFactor || 0).toFixed(3),
        npu: +(this._queues[Device.NPU]?.loadFactor || 0).toFixed(3),
        cpu: +(this._queues[Device.CPU]?.loadFactor || 0).toFixed(3),
      },
    };
  }

  /**
   * Full scheduler status for /health and monitoring.
   */
  getStatus() {
    const deviceStatus = {};
    for (const dev of Object.keys(this._queues)) {
      deviceStatus[dev] = {
        queue: this._queues[dev].getStatus(),
        circuitBreaker: this._breakers[dev].getStatus(),
        activeJobs: this._activeJobs[dev].size,
        avgLatencyMs: +(this._avgLatency[dev] || 0).toFixed(2),
      };
    }

    return {
      initialized: this._initialized,
      devices: deviceStatus,
      routing: {
        mode: this._useMLRouting && this._mlAccuracy >= 0.5 ? 'ml' : 'rules',
        mlAccuracy: +(this._mlAccuracy.toFixed(3)),
        mlDecisions: this._stats.mlRoutingDecisions,
        ruleDecisions: this._stats.ruleRoutingDecisions,
      },
      stats: { ...this._stats },
      trainingData: this._trainingLog.getStatus(),
      burstRate: {
        last10ms: this._getBurstRate(10),
        last100ms: this._getBurstRate(100),
      },
    };
  }

  /**
   * Graceful shutdown. Drains all queues, rejects pending with reason.
   */
  async shutdown() {
    this._shutdownRequested = true;
    if (this._giftTimer) clearInterval(this._giftTimer);

    // Drain all queues
    for (const [dev, queue] of Object.entries(this._queues)) {
      const remaining = queue.drain();
      for (const task of remaining) {
        if (task.timer) clearTimeout(task.timer);
        task.reject({ outcome: Outcome.REJECTED, reason: 'scheduler-shutdown', taskId: task.id });
      }
    }

    // Clear pending
    for (const [id, task] of this._pendingTasks) {
      if (task.timer) clearTimeout(task.timer);
      task.reject({ outcome: Outcome.REJECTED, reason: 'scheduler-shutdown', taskId: id });
    }
    this._pendingTasks.clear();

    log.info(`Scheduler: shutdown complete — ${this._stats.totalCompleted} tasks completed lifetime`);
  }

  /**
   * Get training data for model training.
   * @param {number} n — max entries
   */
  getTrainingData(n = 5000) {
    return this._trainingLog.getRecent(n);
  }

  // =========================================================================
  // MESH PEER AWARENESS — Phase 6
  // =========================================================================

  /**
   * Register a mesh peer's hardware capabilities.
   * Called when HELLO/WELCOME arrives with capabilities payload.
   * @param {string} nodeId
   * @param {Object} caps — from getCapabilities() on remote node
   */
  addMeshPeer(nodeId, caps) {
    if (!this._meshPeers) this._meshPeers = new Map();
    this._meshPeers.set(nodeId, {
      nvGpu: caps.nvGpu || false,
      nvGpuTops: caps.nvGpuTops || 0,
      amdNpu: caps.amdNpu || false,
      amdNpuTops: caps.amdNpuTops || 0,
      totalTops: caps.totalTops || 0,
      onnxProviders: caps.onnxProviders || [],
      addedAt: performance.now(),
    });
  }

  /**
   * Remove a mesh peer (disconnected).
   * @param {string} nodeId
   */
  removeMeshPeer(nodeId) {
    this._meshPeers?.delete(nodeId);
  }

  /**
   * Find the best execution target for a descriptor —
   * compares LOCAL hardware vs all known mesh peers.
   *
   * Returns { nodeId: null } for local execution,
   * or { nodeId: 'abc...' } for remote peer routing.
   *
   * @param {Object} descriptor — { affinity, priority }
   * @returns {{ nodeId: string|null, totalTops: number, reason: string }}
   */
  findBestPeer(descriptor = {}) {
    const localTops = HW.totalTops || 0;
    let best = { nodeId: null, totalTops: localTops, reason: 'local' };

    if (!this._meshPeers || this._meshPeers.size === 0) return best;

    const wantsGpu = descriptor.affinity === Affinity.GPU_PREFERRED;
    const wantsNpu = descriptor.affinity === Affinity.NPU_PREFERRED;

    for (const [nodeId, caps] of this._meshPeers) {
      // Skip peers without the requested accelerator
      if (wantsGpu && !caps.nvGpu) continue;
      if (wantsNpu && !caps.amdNpu) continue;

      if (caps.totalTops > best.totalTops) {
        best = { nodeId, totalTops: caps.totalTops, reason: 'mesh-peer' };
      }
    }

    return best;
  }

  /**
   * Get all known mesh peer capabilities (for status endpoints).
   * @returns {Array<{nodeId, totalTops, nvGpu, amdNpu}>}
   */
  getMeshPeers() {
    if (!this._meshPeers) return [];
    return Array.from(this._meshPeers.entries()).map(([nodeId, caps]) => ({
      nodeId,
      totalTops: caps.totalTops,
      nvGpu: caps.nvGpu,
      nvGpuTops: caps.nvGpuTops,
      amdNpu: caps.amdNpu,
      amdNpuTops: caps.amdNpuTops,
    }));
  }
}

// Singleton scheduler
export const scheduler = new ComputeScheduler();


// =============================================================================
// AGGREGATE INITIALIZER
// =============================================================================

/**
 * Initialize the full acceleration stack.
 * Call once at yakmesh startup. Probes hardware, sets up batch queue,
 * initializes inference engine.
 * 
 * @returns {{ hw: typeof HW, telemetry: Object }}
 */
export async function initialize() {
  await probe();
  await batchVerify.initialize();
  await inference.initialize();
  await scheduler.initialize();

  // Pre-load native PQ if available
  if (HW.nativePQ) {
    await _loadNativePQ();
  }

  return { hw: HW, telemetry: getTelemetry() };
}

// =============================================================================
// TELEMETRY & STATUS
// =============================================================================

/**
 * Get current telemetry snapshot.
 */
export function getTelemetry() {
  const elapsed = Date.now() - telemetry.lastReset;

  return {
    ...telemetry,
    elapsedMs: elapsed,
    sha3NativeRate: telemetry.sha3Calls > 0
      ? (telemetry.sha3NativeHits / telemetry.sha3Calls * 100).toFixed(1) + '%'
      : 'N/A',
    signNativeRate: telemetry.signCalls > 0
      ? (telemetry.signNativeHits / telemetry.signCalls * 100).toFixed(1) + '%'
      : 'N/A',
    verifyNativeRate: telemetry.verifyCalls > 0
      ? (telemetry.verifyNativeHits / telemetry.verifyCalls * 100).toFixed(1) + '%'
      : 'N/A',
    inferAccelRate: telemetry.inferCalls > 0
      ? ((telemetry.inferNpuHits + telemetry.inferGpuHits) / telemetry.inferCalls * 100).toFixed(1) + '%'
      : 'N/A',
  };
}

/**
 * Reset telemetry counters.
 */
export function resetTelemetry() {
  Object.keys(telemetry).forEach(k => {
    if (k !== 'lastReset') telemetry[k] = 0;
  });
  telemetry.lastReset = Date.now();
}

/**
 * Get a human-readable status report.
 */
export function getStatus() {
  const t = getTelemetry();

  return {
    hardware: {
      cpu: HW.cpuModel,
      arch: HW.cpuArch,
      threads: HW.threads,
      simd: {
        avx512: HW.avx512,
        vaes: HW.vaes,
        shaNI: HW.shaNI,
        gfni: HW.gfni,
      },
      gpu: HW.nvGpu ? {
        name: HW.nvGpuName,
        vram: `${HW.nvGpuVRAM} MiB`,
        compute: HW.nvComputeCap,
        cuda: HW.nvCudaVersion,
        tops: HW.nvGpuTops,
      } : null,
      npu: HW.amdNpu ? {
        tops: HW.amdNpuTops,
      } : null,
      totalTops: HW.totalTops,
    },
    acceleration: {
      sha3: HW.nativeSha3 ? 'native (OpenSSL)' : 'pure-JS (@noble)',
      pqCrypto: HW.nativePQ ? `native (${HW.nativePQBackend})` : 'pure-JS (@noble)',
      batchVerify: batchVerify._poolReady
        ? `Worker pool (${batchVerify._workers.length} threads)${batchVerify._gpuAvailable ? ' + CUDA detected' : ''}`
        : batchVerify._gpuAvailable ? 'GPU (CUDA)' : 'CPU sequential',
      inference: inference.provider,
    },
    scheduler: scheduler.getStatus(),
    telemetry: t,
  };
}

// =============================================================================
// HARDWARE CAPABILITIES SNAPSHOT
// =============================================================================

/**
 * Returns a compact snapshot of hardware capabilities for mesh sharing.
 * Sent in HELLO/WELCOME payloads so peers know each other's compute profile.
 */
export function getCapabilities() {
  return {
    avx512: HW.avx512,
    vaes: HW.vaes,
    shaNI: HW.shaNI,
    gfni: HW.gfni,
    nvGpu: HW.nvGpu,
    nvGpuName: HW.nvGpuName || undefined,
    nvGpuVRAM: HW.nvGpuVRAM || undefined,
    nvGpuTops: HW.nvGpuTops || undefined,
    amdNpu: HW.amdNpu,
    amdNpuTops: HW.amdNpuTops || undefined,
    totalTops: HW.totalTops,
    onnxProviders: HW.onnxProviders.length ? HW.onnxProviders : undefined,
  };
}

// =============================================================================
// CONVENIENCE RE-EXPORTS
// =============================================================================

// Re-export @noble utilities so consumers can import from accel
export { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// Direct pass-through for operations not yet accelerated
export { randomBytes };

export default {
  probe,
  initialize,
  sha3_256,
  sha3_256hex,
  mlDsa65Keygen,
  mlDsa65Sign,
  mlDsa65Verify,
  mlKem768Keygen,
  mlKem768Encapsulate,
  mlKem768Decapsulate,
  batchVerify,
  inference,
  scheduler,
  Priority,
  Device,
  Affinity,
  getTelemetry,
  resetTelemetry,
  getStatus,
  getCapabilities,
  HW,
};
