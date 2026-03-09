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
 * ACCEL — Adaptive Compute & Crypto Engine Layer Tests
 * 
 * Tests hardware acceleration detection, crypto primitive wiring,
 * and performance regression against pure-JS baseline.
 * 
 * @module utils/tests/accel.test
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert';

import {
  probe,
  initialize,
  sha3_256,
  sha3_256hex,
  mlDsa65Sign,
  mlDsa65Verify,
  mlKem768Encapsulate,
  mlKem768Decapsulate,
  batchVerify,
  inference,
  getTelemetry,
  resetTelemetry,
  getStatus,
  HW,
} from '../accel.js';

// Pure JS references for correctness comparison
import { sha3_256 as nobleSha3 } from '@noble/hashes/sha3.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

console.log('\n⚡ ACCEL — Hardware Acceleration Engine Tests\n');
console.log('='.repeat(60));

// =============================================================================
// HARDWARE PROBE
// =============================================================================

describe('ACCEL: Hardware Probe', () => {
  before(async () => {
    await probe();
  });
  
  it('detects CPU model and architecture', () => {
    assert.ok(HW.cpuModel.length > 0, 'CPU model should be detected');
    assert.ok(HW.cpuArch.length > 0, 'CPU arch should be detected');
    assert.ok(HW.threads > 0, 'Thread count should be > 0');
    console.log(`  CPU: ${HW.cpuModel} (${HW.threads} threads)`);
  });
  
  it('detects SHA3 native support', () => {
    // Node.js 16+ with OpenSSL 1.1.1+ should have native SHA3
    assert.strictEqual(typeof HW.nativeSha3, 'boolean');
    console.log(`  SHA3 native: ${HW.nativeSha3 ? '✓ OpenSSL' : '✗ pure JS'}`);
  });
  
  it('detects CPU SIMD features', () => {
    assert.strictEqual(typeof HW.avx512, 'boolean');
    assert.strictEqual(typeof HW.vaes, 'boolean');
    assert.strictEqual(typeof HW.shaNI, 'boolean');
    assert.strictEqual(typeof HW.gfni, 'boolean');
    
    const simd = [];
    if (HW.avx512) simd.push('AVX-512');
    if (HW.vaes) simd.push('VAES');
    if (HW.shaNI) simd.push('SHA-NI');
    if (HW.gfni) simd.push('GFNI');
    console.log(`  SIMD: ${simd.length > 0 ? simd.join(', ') : 'none detected'}`);
  });
  
  it('probes NVIDIA GPU (if present)', () => {
    assert.strictEqual(typeof HW.nvGpu, 'boolean');
    if (HW.nvGpu) {
      assert.ok(HW.nvGpuName.length > 0, 'GPU name should be set');
      assert.ok(HW.nvGpuVRAM > 0, 'VRAM should be > 0');
      console.log(`  GPU: ${HW.nvGpuName} (${HW.nvGpuVRAM} MiB, CUDA ${HW.nvCudaVersion})`);
    } else {
      console.log('  GPU: not detected');
    }
  });
  
  it('probes AMD NPU (if present)', () => {
    assert.strictEqual(typeof HW.amdNpu, 'boolean');
    if (HW.amdNpu) {
      assert.ok(HW.amdNpuTops > 0, 'TOPS should be > 0');
      console.log(`  NPU: AMD XDNA ${HW.amdNpuTops} TOPS`);
    } else {
      console.log('  NPU: not detected');
    }
  });
  
  it('returns complete status report', () => {
    const status = getStatus();
    assert.ok(status.hardware, 'status should have hardware section');
    assert.ok(status.acceleration, 'status should have acceleration section');
    assert.ok(status.telemetry, 'status should have telemetry section');
    console.log(`  Acceleration: SHA3=${status.acceleration.sha3}, PQ=${status.acceleration.pqCrypto}`);
  });
});

// =============================================================================
// SHA3-256 ACCELERATION
// =============================================================================

describe('ACCEL: SHA3-256 (native OpenSSL vs pure JS)', () => {
  before(async () => {
    await probe();
    resetTelemetry();
  });
  
  it('produces identical output to @noble/hashes', () => {
    const inputs = [
      new Uint8Array(0),                           // empty
      new Uint8Array([0x59, 0x41, 0x4B]),          // "YAK"
      new Uint8Array(32).fill(0xFF),               // 32 bytes of 0xFF
      new Uint8Array(4096).fill(0xAB),             // 4KB
      crypto.getRandomValues(new Uint8Array(256)), // random 256 bytes
    ];
    
    for (const input of inputs) {
      const accelResult = sha3_256(input);
      const nobleResult = nobleSha3(input);
      
      assert.deepStrictEqual(
        accelResult,
        nobleResult,
        `SHA3-256 mismatch for ${input.length}-byte input`
      );
    }
    
    console.log('  ✓ All 5 test vectors match @noble/hashes output');
  });
  
  it('handles string input', () => {
    const strResult = sha3_256('yakmesh');
    const bytesResult = sha3_256(new TextEncoder().encode('yakmesh'));
    
    assert.deepStrictEqual(strResult, bytesResult,
      'String vs Uint8Array should produce same hash');
    console.log('  ✓ String/bytes interop verified');
  });
  
  it('sha3_256hex returns correct hex encoding', () => {
    const hex = sha3_256hex('yakmesh');
    assert.strictEqual(hex.length, 64, 'SHA3-256 hex should be 64 chars');
    assert.match(hex, /^[0-9a-f]{64}$/, 'Should be valid lowercase hex');
    
    const manual = bytesToHex(sha3_256('yakmesh'));
    assert.strictEqual(hex, manual, 'sha3_256hex should match manual hex encoding');
    console.log(`  ✓ sha3_256hex: ${hex.slice(0, 16)}...`);
  });
  
  it('is faster than @noble/hashes (performance regression test)', () => {
    const data = new Uint8Array(256);
    const N = 5000;
    
    // Warmup
    for (let i = 0; i < 100; i++) { sha3_256(data); nobleSha3(data); }
    
    const t0 = performance.now();
    for (let i = 0; i < N; i++) sha3_256(data);
    const accelTime = performance.now() - t0;
    
    const t1 = performance.now();
    for (let i = 0; i < N; i++) nobleSha3(data);
    const nobleTime = performance.now() - t1;
    
    const speedup = nobleTime / accelTime;
    
    console.log(`  ACCEL SHA3 x${N}: ${accelTime.toFixed(2)}ms`);
    console.log(`  Noble SHA3 x${N}: ${nobleTime.toFixed(2)}ms`);
    console.log(`  Speedup: ${speedup.toFixed(1)}x`);
    
    if (HW.nativeSha3) {
      // Native should be faster
      assert.ok(speedup > 1.5, `Expected >1.5x speedup with native SHA3, got ${speedup.toFixed(1)}x`);
    }
  });
  
  it('tracks telemetry correctly', () => {
    resetTelemetry();
    sha3_256('test1');
    sha3_256('test2');
    sha3_256('test3');
    
    const t = getTelemetry();
    assert.strictEqual(t.sha3Calls, 3, 'Should record 3 SHA3 calls');
    
    if (HW.nativeSha3) {
      assert.strictEqual(t.sha3NativeHits, 3, 'All calls should hit native path');
      assert.strictEqual(t.sha3NativeRate, '100.0%');
    }
    
    console.log(`  ✓ Telemetry: ${t.sha3Calls} calls, native rate: ${t.sha3NativeRate}`);
  });
});

// =============================================================================
// ML-DSA-65 ACCELERATION
// =============================================================================

describe('ACCEL: ML-DSA-65 (Dilithium3)', () => {
  let kp;
  const message = new Uint8Array(256);
  
  before(async () => {
    await probe();
    crypto.getRandomValues(message);
    const seed = crypto.getRandomValues(new Uint8Array(32));
    kp = ml_dsa65.keygen(seed);
  });
  
  it('sign produces valid signature verifiable by @noble', () => {
    const sig = mlDsa65Sign(message, kp.secretKey);
    assert.ok(sig instanceof Uint8Array, 'Signature should be Uint8Array');
    assert.ok(sig.length > 0, 'Signature should not be empty');
    
    // Verify with pure @noble (cross-check)
    const valid = ml_dsa65.verify(sig, message, kp.publicKey);
    assert.ok(valid, 'ACCEL signature should verify with @noble');
    console.log(`  ✓ ACCEL sign → @noble verify: valid (sig ${sig.length} bytes)`);
  });
  
  it('verify matches @noble verify result', () => {
    const sig = ml_dsa65.sign(message, kp.secretKey);
    
    const accelResult = mlDsa65Verify(sig, message, kp.publicKey);
    const nobleResult = ml_dsa65.verify(sig, message, kp.publicKey);
    
    assert.strictEqual(accelResult, nobleResult, 'Verify results should match');
    assert.ok(accelResult, 'Signature should be valid');
    console.log('  ✓ ACCEL verify matches @noble verify');
  });
  
  it('rejects invalid signatures', () => {
    const sig = mlDsa65Sign(message, kp.secretKey);
    
    // Corrupt signature
    const corrupted = new Uint8Array(sig);
    corrupted[0] ^= 0xFF;
    
    const result = mlDsa65Verify(corrupted, message, kp.publicKey);
    assert.strictEqual(result, false, 'Corrupted signature should fail');
    console.log('  ✓ Correctly rejects corrupted signature');
  });
  
  it('rejects wrong message', () => {
    const sig = mlDsa65Sign(message, kp.secretKey);
    const wrongMessage = new Uint8Array(256);
    crypto.getRandomValues(wrongMessage);
    
    const result = mlDsa65Verify(sig, wrongMessage, kp.publicKey);
    assert.strictEqual(result, false, 'Wrong message should fail verification');
    console.log('  ✓ Correctly rejects wrong message');
  });
  
  it('tracks sign/verify telemetry', () => {
    resetTelemetry();
    
    const sig = mlDsa65Sign(message, kp.secretKey);
    mlDsa65Verify(sig, message, kp.publicKey);
    
    const t = getTelemetry();
    assert.strictEqual(t.signCalls, 1, 'Should record 1 sign call');
    assert.strictEqual(t.verifyCalls, 1, 'Should record 1 verify call');
    console.log(`  ✓ Telemetry: sign=${t.signCalls} verify=${t.verifyCalls}`);
  });
});

// =============================================================================
// ML-KEM-768 ACCELERATION
// =============================================================================

describe('ACCEL: ML-KEM-768 (Kyber)', () => {
  let kp;
  
  before(async () => {
    await probe();
    const seed = crypto.getRandomValues(new Uint8Array(64));
    kp = ml_kem768.keygen(seed);
  });
  
  it('encapsulate/decapsulate produce matching shared secrets', () => {
    const enc = mlKem768Encapsulate(kp.publicKey);
    assert.ok(enc.cipherText, 'Should produce cipherText');
    assert.ok(enc.sharedSecret, 'Should produce sharedSecret');
    
    const dec = mlKem768Decapsulate(enc.cipherText, kp.secretKey);
    assert.deepStrictEqual(dec, enc.sharedSecret,
      'Decapsulated secret should match encapsulated secret');
    
    console.log(`  ✓ KEM round-trip: shared secret ${enc.sharedSecret.length} bytes`);
  });
  
  it('cross-verifies with @noble encapsulate', () => {
    // Encapsulate with @noble, decapsulate with ACCEL
    const enc = ml_kem768.encapsulate(kp.publicKey);
    const dec = mlKem768Decapsulate(enc.cipherText, kp.secretKey);
    assert.deepStrictEqual(dec, enc.sharedSecret);
    
    // Encapsulate with ACCEL, decapsulate with @noble
    const enc2 = mlKem768Encapsulate(kp.publicKey);
    const dec2 = ml_kem768.decapsulate(enc2.cipherText, kp.secretKey);
    assert.deepStrictEqual(dec2, enc2.sharedSecret);
    
    console.log('  ✓ Cross-verification: ACCEL ↔ @noble KEM interop');
  });
  
  it('tracks KEM telemetry', () => {
    resetTelemetry();
    
    const enc = mlKem768Encapsulate(kp.publicKey);
    mlKem768Decapsulate(enc.cipherText, kp.secretKey);
    
    const t = getTelemetry();
    assert.strictEqual(t.kemCalls, 2, 'Should record 2 KEM calls');
    console.log(`  ✓ Telemetry: kem=${t.kemCalls}`);
  });
});

// =============================================================================
// BATCH VERIFY QUEUE
// =============================================================================

describe('ACCEL: Batch Verify Queue', () => {
  let kp;
  const message = new Uint8Array(128);
  
  before(async () => {
    await initialize();
    crypto.getRandomValues(message);
    const seed = crypto.getRandomValues(new Uint8Array(32));
    kp = ml_dsa65.keygen(seed);
  });
  
  it('processes single enqueued verification', async () => {
    const sig = ml_dsa65.sign(message, kp.secretKey);
    const result = await batchVerify.enqueue(sig, message, kp.publicKey);
    assert.strictEqual(result, true, 'Valid signature should pass batch verify');
    console.log('  ✓ Single batch verify: passed');
  });
  
  it('processes multiple verifications in batch', async () => {
    const sigs = [];
    for (let i = 0; i < 5; i++) {
      const msg = new Uint8Array(64);
      crypto.getRandomValues(msg);
      sigs.push({
        sig: ml_dsa65.sign(msg, kp.secretKey),
        msg,
      });
    }
    
    const results = await Promise.all(
      sigs.map(s => batchVerify.enqueue(s.sig, s.msg, kp.publicKey))
    );
    
    assert.strictEqual(results.length, 5);
    assert.ok(results.every(r => r === true), 'All valid sigs should pass');
    console.log('  ✓ Batch of 5 verifications: all passed');
  });
  
  it('rejects invalid signature in batch', async () => {
    const sig = ml_dsa65.sign(message, kp.secretKey);
    const corrupted = new Uint8Array(sig);
    corrupted[0] ^= 0xFF;
    
    const result = await batchVerify.enqueue(corrupted, message, kp.publicKey);
    assert.strictEqual(result, false, 'Corrupted sig should fail in batch');
    console.log('  ✓ Batch correctly rejects invalid signature');
  });
});

// =============================================================================
// INFERENCE ENGINE
// =============================================================================

describe('ACCEL: Inference Engine', () => {
  it('initializes without crash (even without ONNX Runtime)', async () => {
    await inference.initialize();
    assert.strictEqual(typeof inference.isAccelerated, 'boolean');
    assert.strictEqual(typeof inference.provider, 'string');
    console.log(`  ✓ Inference engine: provider=${inference.provider}, accelerated=${inference.isAccelerated}`);
  });
  
  it('returns null for unloaded models', async () => {
    const result = await inference.infer('nonexistent-model', {
      features: new Float32Array([1, 2, 3]),
    });
    assert.strictEqual(result, null);
    console.log('  ✓ Gracefully returns null for missing model');
  });
  
  it('reports model availability correctly', () => {
    assert.strictEqual(inference.hasModel('sakshi-anomaly'), false);
    assert.strictEqual(inference.hasModel('karma-trust'), false);
    console.log('  ✓ hasModel returns false for unloaded models');
  });
});

// =============================================================================
// FULL INITIALIZATION
// =============================================================================

describe('ACCEL: Full Stack Initialize', () => {
  it('initialize() sets up all subsystems', async () => {
    const result = await initialize();
    assert.ok(result.hw, 'Should return hardware info');
    assert.ok(result.telemetry, 'Should return telemetry');
    console.log('  ✓ Full stack initialized');
    
    console.log('\n' + '='.repeat(60));
    console.log('  ACCEL Hardware Summary:');
    console.log(`    CPU:     ${HW.cpuModel}`);
    console.log(`    SHA3:    ${HW.nativeSha3 ? '⚡ native (OpenSSL)' : '○ pure JS'}`);
    console.log(`    AVX-512: ${HW.avx512 ? '⚡' : '○'}`);
    console.log(`    VAES:    ${HW.vaes ? '⚡' : '○'}`);
    console.log(`    SHA-NI:  ${HW.shaNI ? '⚡' : '○'}`);
    console.log(`    GPU:     ${HW.nvGpu ? '⚡ ' + HW.nvGpuName : '○ none'}`);
    console.log(`    NPU:     ${HW.amdNpu ? '⚡ ' + HW.amdNpuTops + ' TOPS' : '○ none'}`);
    console.log(`    PQ:      ${HW.nativePQ ? '⚡ ' + HW.nativePQBackend : '○ @noble pure JS'}`);
    console.log(`    ONNX:    ${HW.onnxRuntime ? '⚡ ' + HW.onnxProviders.join(',') : '○ not installed'}`);
    console.log('='.repeat(60));
  });
});
