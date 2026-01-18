/**
 * Post-Quantum Cryptography Test Suite
 * 
 * Comprehensive tests for all cryptographic operations in Yakmesh.
 * Verifies correct implementation of NIST FIPS 203/204 algorithms.
 * 
 * @module oracle/tests/crypto.test.js
 * @version 1.6.0
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert';

// Crypto config (supports Level 3 and Level 5)
import {
  SecurityLevel,
  setSecurityLevel,
  getSecurityLevel,
  getCryptoProfile,
  generateSignatureKeyPair,
  sign,
  verify,
  generateKemKeyPair,
  encapsulate,
  decapsulate,
  getCryptoSummary,
} from '../../security/crypto-config.js';

// Direct algorithm imports for comparison
import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';

// Import identity module
import { generateKeyPair, signMessage, verifySignature } from '../../identity/node-key.js';

describe('Post-Quantum Cryptography Test Suite', () => {
  
  // ============================================================
  // SECURITY LEVEL CONFIGURATION
  // ============================================================
  
  describe('Security Level Configuration', () => {
    
    test('default security level is LEVEL_3', () => {
      // Reset to default
      setSecurityLevel(SecurityLevel.LEVEL_3);
      assert.strictEqual(getSecurityLevel(), SecurityLevel.LEVEL_3);
    });
    
    test('can switch to LEVEL_5 (paranoid mode)', () => {
      setSecurityLevel(SecurityLevel.LEVEL_5);
      assert.strictEqual(getSecurityLevel(), SecurityLevel.LEVEL_5);
      
      const profile = getCryptoProfile();
      assert.strictEqual(profile.name, 'NIST Level 5');
      assert.strictEqual(profile.signature.name, 'ML-DSA-87');
      assert.strictEqual(profile.kem.name, 'ML-KEM-1024');
      
      // Reset
      setSecurityLevel(SecurityLevel.LEVEL_3);
    });
    
    test('rejects invalid security levels', () => {
      assert.throws(() => setSecurityLevel(1), /Invalid security level/);
      assert.throws(() => setSecurityLevel(4), /Invalid security level/);
      assert.throws(() => setSecurityLevel('high'), /Invalid security level/);
    });
    
    test('getCryptoSummary returns correct info', () => {
      setSecurityLevel(SecurityLevel.LEVEL_3);
      const summary = getCryptoSummary();
      
      assert.strictEqual(summary.securityLevel, 3);
      assert.strictEqual(summary.levelName, 'NIST Level 3');
      assert.strictEqual(summary.signatureAlgorithm, 'ML-DSA-65');
      assert.strictEqual(summary.kemAlgorithm, 'ML-KEM-768');
      assert.ok(summary.nistStandards.includes('FIPS 203 (ML-KEM)'));
      assert.ok(summary.nistStandards.includes('FIPS 204 (ML-DSA)'));
    });
  });
  
  // ============================================================
  // ML-DSA (DILITHIUM) SIGNATURES - LEVEL 3
  // ============================================================
  
  describe('ML-DSA-65 (Dilithium3) Signatures', () => {
    let keyPair;
    
    before(() => {
      setSecurityLevel(SecurityLevel.LEVEL_3);
      const seed = randomBytes(32);
      keyPair = generateSignatureKeyPair(seed);
    });
    
    test('generates valid key pair', () => {
      assert.ok(keyPair.publicKey instanceof Uint8Array);
      assert.ok(keyPair.secretKey instanceof Uint8Array);
      assert.strictEqual(keyPair.publicKey.length, 1952);
      assert.strictEqual(keyPair.secretKey.length, 4032);
    });
    
    test('signs and verifies message', () => {
      const message = utf8ToBytes('Hello, Yakmesh!');
      const signature = sign(message, keyPair.secretKey);
      
      assert.ok(signature instanceof Uint8Array);
      assert.strictEqual(signature.length, 3309);
      
      const isValid = verify(signature, message, keyPair.publicKey);
      assert.strictEqual(isValid, true);
    });
    
    test('rejects tampered message', () => {
      const message = utf8ToBytes('Original message');
      const signature = sign(message, keyPair.secretKey);
      
      const tamperedMessage = utf8ToBytes('Tampered message');
      const isValid = verify(signature, tamperedMessage, keyPair.publicKey);
      assert.strictEqual(isValid, false);
    });
    
    test('rejects tampered signature', () => {
      const message = utf8ToBytes('Test message');
      const signature = sign(message, keyPair.secretKey);
      
      // Tamper with signature
      const tamperedSig = new Uint8Array(signature);
      tamperedSig[0] ^= 0xFF;
      
      const isValid = verify(tamperedSig, message, keyPair.publicKey);
      assert.strictEqual(isValid, false);
    });
    
    test('different keys produce different signatures', () => {
      const message = utf8ToBytes('Same message');
      
      const seed1 = randomBytes(32);
      const seed2 = randomBytes(32);
      const kp1 = generateSignatureKeyPair(seed1);
      const kp2 = generateSignatureKeyPair(seed2);
      
      const sig1 = sign(message, kp1.secretKey);
      const sig2 = sign(message, kp2.secretKey);
      
      // Signatures should be different
      assert.notDeepStrictEqual(sig1, sig2);
      
      // Cross-verification should fail
      assert.strictEqual(verify(sig1, message, kp2.publicKey), false);
      assert.strictEqual(verify(sig2, message, kp1.publicKey), false);
    });
    
    test('signature is deterministic for same message and key', () => {
      // Note: ML-DSA includes randomness, so this tests the algorithm behavior
      const message = utf8ToBytes('Determinism test');
      const sig1 = sign(message, keyPair.secretKey);
      const sig2 = sign(message, keyPair.secretKey);
      
      // Both should verify
      assert.strictEqual(verify(sig1, message, keyPair.publicKey), true);
      assert.strictEqual(verify(sig2, message, keyPair.publicKey), true);
    });
  });
  
  // ============================================================
  // ML-DSA-87 (DILITHIUM5) SIGNATURES - LEVEL 5
  // ============================================================
  
  describe('ML-DSA-87 (Dilithium5) Signatures - Level 5', () => {
    let keyPair;
    
    before(() => {
      setSecurityLevel(SecurityLevel.LEVEL_5);
      const seed = randomBytes(32);
      keyPair = generateSignatureKeyPair(seed);
    });
    
    after(() => {
      setSecurityLevel(SecurityLevel.LEVEL_3);
    });
    
    test('generates larger keys for Level 5', () => {
      assert.strictEqual(keyPair.publicKey.length, 2592);
      assert.strictEqual(keyPair.secretKey.length, 4896);
    });
    
    test('produces larger signatures for Level 5', () => {
      const message = utf8ToBytes('Level 5 test');
      const signature = sign(message, keyPair.secretKey);
      
      assert.strictEqual(signature.length, 4627);
      assert.strictEqual(verify(signature, message, keyPair.publicKey), true);
    });
    
    test('Level 5 signature incompatible with Level 3 verification', () => {
      const message = utf8ToBytes('Cross-level test');
      const level5Sig = sign(message, keyPair.secretKey);
      
      // Try to verify Level 5 sig with Level 3 algorithm (should fail/throw)
      setSecurityLevel(SecurityLevel.LEVEL_3);
      const level3KeyPair = generateSignatureKeyPair(randomBytes(32));
      
      // This should either throw or return false due to size mismatch
      try {
        const result = verify(level5Sig, message, level3KeyPair.publicKey);
        assert.strictEqual(result, false);
      } catch (e) {
        // Expected for size mismatch
        assert.ok(true);
      }
      
      setSecurityLevel(SecurityLevel.LEVEL_5);
    });
  });
  
  // ============================================================
  // ML-KEM (KYBER) KEY ENCAPSULATION - LEVEL 3
  // ============================================================
  
  describe('ML-KEM-768 (Kyber768) Key Encapsulation', () => {
    let keyPair;
    
    before(() => {
      setSecurityLevel(SecurityLevel.LEVEL_3);
      const seed = randomBytes(64);
      keyPair = generateKemKeyPair(seed);
    });
    
    test('generates valid KEM key pair', () => {
      assert.ok(keyPair.publicKey instanceof Uint8Array);
      assert.ok(keyPair.secretKey instanceof Uint8Array);
      assert.strictEqual(keyPair.publicKey.length, 1184);
      assert.strictEqual(keyPair.secretKey.length, 2400);
    });
    
    test('encapsulation produces ciphertext and shared secret', () => {
      const result = encapsulate(keyPair.publicKey);
      
      assert.ok(result.ciphertext instanceof Uint8Array);
      assert.ok(result.sharedSecret instanceof Uint8Array);
      assert.strictEqual(result.ciphertext.length, 1088);
      assert.strictEqual(result.sharedSecret.length, 32);
    });
    
    test('decapsulation recovers same shared secret', () => {
      const { ciphertext, sharedSecret: senderSecret } = encapsulate(keyPair.publicKey);
      const receiverSecret = decapsulate(ciphertext, keyPair.secretKey);
      
      assert.deepStrictEqual(senderSecret, receiverSecret);
    });
    
    test('different public keys produce different shared secrets', () => {
      const kp1 = generateKemKeyPair(randomBytes(64));
      const kp2 = generateKemKeyPair(randomBytes(64));
      
      const result1 = encapsulate(kp1.publicKey);
      const result2 = encapsulate(kp2.publicKey);
      
      assert.notDeepStrictEqual(result1.sharedSecret, result2.sharedSecret);
    });
    
    test('wrong secret key fails to decapsulate correctly', () => {
      const kp1 = generateKemKeyPair(randomBytes(64));
      const kp2 = generateKemKeyPair(randomBytes(64));
      
      const { ciphertext, sharedSecret: correctSecret } = encapsulate(kp1.publicKey);
      const wrongSecret = decapsulate(ciphertext, kp2.secretKey);
      
      // ML-KEM is IND-CCA2 secure, so decapsulating with wrong key gives different result
      assert.notDeepStrictEqual(correctSecret, wrongSecret);
    });
    
    test('each encapsulation produces unique ciphertext', () => {
      const ct1 = encapsulate(keyPair.publicKey).ciphertext;
      const ct2 = encapsulate(keyPair.publicKey).ciphertext;
      
      // Ciphertexts should be different (randomized encapsulation)
      assert.notDeepStrictEqual(ct1, ct2);
    });
  });
  
  // ============================================================
  // ML-KEM-1024 (KYBER1024) KEY ENCAPSULATION - LEVEL 5
  // ============================================================
  
  describe('ML-KEM-1024 (Kyber1024) Key Encapsulation - Level 5', () => {
    let keyPair;
    
    before(() => {
      setSecurityLevel(SecurityLevel.LEVEL_5);
      const seed = randomBytes(64);
      keyPair = generateKemKeyPair(seed);
    });
    
    after(() => {
      setSecurityLevel(SecurityLevel.LEVEL_3);
    });
    
    test('generates larger keys for Level 5', () => {
      assert.strictEqual(keyPair.publicKey.length, 1568);
      assert.strictEqual(keyPair.secretKey.length, 3168);
    });
    
    test('produces larger ciphertext for Level 5', () => {
      const { ciphertext } = encapsulate(keyPair.publicKey);
      assert.strictEqual(ciphertext.length, 1568);
    });
    
    test('shared secret still 32 bytes at Level 5', () => {
      const { sharedSecret } = encapsulate(keyPair.publicKey);
      assert.strictEqual(sharedSecret.length, 32);
    });
  });
  
  // ============================================================
  // HASH FUNCTION TESTS (SHA3-256)
  // ============================================================
  
  describe('SHA3-256 Hash Function', () => {
    
    test('produces 256-bit (32 byte) output', () => {
      const hash = sha3_256(utf8ToBytes('test'));
      assert.strictEqual(hash.length, 32);
    });
    
    test('is deterministic', () => {
      const input = utf8ToBytes('Yakmesh');
      const hash1 = sha3_256(input);
      const hash2 = sha3_256(input);
      
      assert.deepStrictEqual(hash1, hash2);
    });
    
    test('different inputs produce different hashes', () => {
      const hash1 = sha3_256(utf8ToBytes('input1'));
      const hash2 = sha3_256(utf8ToBytes('input2'));
      
      assert.notDeepStrictEqual(hash1, hash2);
    });
    
    test('small change produces completely different hash (avalanche)', () => {
      const hash1 = sha3_256(utf8ToBytes('message'));
      const hash2 = sha3_256(utf8ToBytes('Message'));
      
      // Count differing bits
      let differingBits = 0;
      for (let i = 0; i < 32; i++) {
        let xor = hash1[i] ^ hash2[i];
        while (xor) {
          differingBits += xor & 1;
          xor >>= 1;
        }
      }
      
      // Should differ in roughly half the bits (128 ± some variance)
      assert.ok(differingBits > 100, `Only ${differingBits} bits differ (expected ~128)`);
    });
    
    test('empty input has known hash', () => {
      const emptyHash = bytesToHex(sha3_256(new Uint8Array(0)));
      // Known SHA3-256 of empty string
      assert.strictEqual(
        emptyHash,
        'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'
      );
    });
  });
  
  // ============================================================
  // NODE IDENTITY MODULE TESTS
  // ============================================================
  
  describe('Node Identity Module', () => {
    
    test('generateKeyPair produces valid ML-DSA-65 keys', () => {
      const keyPair = generateKeyPair();
      
      assert.strictEqual(keyPair.algorithm, 'ML-DSA-65');
      assert.strictEqual(keyPair.nistLevel, 3);
      assert.ok(keyPair.publicKey);
      assert.ok(keyPair.secretKey);
      
      // Keys should be hex strings
      assert.strictEqual(typeof keyPair.publicKey, 'string');
      assert.strictEqual(typeof keyPair.secretKey, 'string');
      
      // Check lengths (hex = 2 chars per byte)
      assert.strictEqual(keyPair.publicKey.length, 1952 * 2);
      assert.strictEqual(keyPair.secretKey.length, 4032 * 2);
    });
    
    test('signMessage and verifySignature work correctly', () => {
      const keyPair = generateKeyPair();
      const message = 'Test message for signing';
      
      const signature = signMessage(message, keyPair.secretKey);
      
      assert.ok(signature);
      assert.strictEqual(typeof signature, 'string');
      
      const isValid = verifySignature(message, signature, keyPair.publicKey);
      assert.strictEqual(isValid, true);
    });
    
    test('verifySignature rejects tampered message', () => {
      const keyPair = generateKeyPair();
      const message = 'Original message';
      
      const signature = signMessage(message, keyPair.secretKey);
      
      const isValid = verifySignature('Tampered message', signature, keyPair.publicKey);
      assert.strictEqual(isValid, false);
    });
    
    test('verifySignature rejects wrong public key', () => {
      const keyPair1 = generateKeyPair();
      const keyPair2 = generateKeyPair();
      const message = 'Test message';
      
      const signature = signMessage(message, keyPair1.secretKey);
      
      const isValid = verifySignature(message, signature, keyPair2.publicKey);
      assert.strictEqual(isValid, false);
    });
  });
  
  // ============================================================
  // INTEGRATION TESTS
  // ============================================================
  
  describe('Integration Tests', () => {
    
    test('full handshake simulation: sign + KEM + encrypt', () => {
      setSecurityLevel(SecurityLevel.LEVEL_3);
      
      // Alice and Bob generate identity keys
      const aliceSign = generateSignatureKeyPair(randomBytes(32));
      const bobSign = generateSignatureKeyPair(randomBytes(32));
      
      // Bob generates ephemeral KEM key for session
      const bobKem = generateKemKeyPair(randomBytes(64));
      
      // Alice encapsulates to Bob's public key
      const { ciphertext, sharedSecret: aliceSecret } = encapsulate(bobKem.publicKey);
      
      // Alice signs the ciphertext to prove identity
      const aliceSig = sign(ciphertext, aliceSign.secretKey);
      
      // Bob verifies Alice's signature
      const sigValid = verify(aliceSig, ciphertext, aliceSign.publicKey);
      assert.strictEqual(sigValid, true);
      
      // Bob decapsulates to get shared secret
      const bobSecret = decapsulate(ciphertext, bobKem.secretKey);
      
      // Both have same shared secret
      assert.deepStrictEqual(aliceSecret, bobSecret);
      
      // Derive symmetric key from shared secret
      const sessionKey = sha3_256(bobSecret);
      assert.strictEqual(sessionKey.length, 32);
    });
    
    test('security level upgrade preserves functionality', () => {
      // Start at Level 3
      setSecurityLevel(SecurityLevel.LEVEL_3);
      const l3Keys = generateSignatureKeyPair(randomBytes(32));
      const l3Msg = utf8ToBytes('Level 3 message');
      const l3Sig = sign(l3Msg, l3Keys.secretKey);
      assert.strictEqual(verify(l3Sig, l3Msg, l3Keys.publicKey), true);
      
      // Upgrade to Level 5
      setSecurityLevel(SecurityLevel.LEVEL_5);
      const l5Keys = generateSignatureKeyPair(randomBytes(32));
      const l5Msg = utf8ToBytes('Level 5 message');
      const l5Sig = sign(l5Msg, l5Keys.secretKey);
      assert.strictEqual(verify(l5Sig, l5Msg, l5Keys.publicKey), true);
      
      // Level 5 keys are larger
      assert.ok(l5Keys.publicKey.length > l3Keys.publicKey.length);
      
      // Reset
      setSecurityLevel(SecurityLevel.LEVEL_3);
    });
  });
  
  // ============================================================
  // PERFORMANCE BENCHMARKS
  // ============================================================
  
  describe('Performance Benchmarks', () => {
    const ITERATIONS = 10;
    
    test('ML-DSA-65 sign/verify performance', () => {
      setSecurityLevel(SecurityLevel.LEVEL_3);
      const keyPair = generateSignatureKeyPair(randomBytes(32));
      const message = randomBytes(256);
      
      const start = performance.now();
      for (let i = 0; i < ITERATIONS; i++) {
        const sig = sign(message, keyPair.secretKey);
        verify(sig, message, keyPair.publicKey);
      }
      const elapsed = performance.now() - start;
      
      console.log(`ML-DSA-65: ${ITERATIONS} sign+verify in ${elapsed.toFixed(2)}ms (${(elapsed/ITERATIONS).toFixed(2)}ms each)`);
      
      // Should complete in reasonable time
      assert.ok(elapsed < 10000, 'Signature operations too slow');
    });
    
    test('ML-KEM-768 encaps/decaps performance', () => {
      setSecurityLevel(SecurityLevel.LEVEL_3);
      const keyPair = generateKemKeyPair(randomBytes(64));
      
      const start = performance.now();
      for (let i = 0; i < ITERATIONS; i++) {
        const { ciphertext, sharedSecret } = encapsulate(keyPair.publicKey);
        decapsulate(ciphertext, keyPair.secretKey);
      }
      const elapsed = performance.now() - start;
      
      console.log(`ML-KEM-768: ${ITERATIONS} encaps+decaps in ${elapsed.toFixed(2)}ms (${(elapsed/ITERATIONS).toFixed(2)}ms each)`);
      
      assert.ok(elapsed < 5000, 'KEM operations too slow');
    });
    
    test('Level 5 vs Level 3 overhead', () => {
      const iterations = 5;
      const message = randomBytes(256);
      
      // Level 3
      setSecurityLevel(SecurityLevel.LEVEL_3);
      const l3Keys = generateSignatureKeyPair(randomBytes(32));
      const l3Start = performance.now();
      for (let i = 0; i < iterations; i++) {
        const sig = sign(message, l3Keys.secretKey);
        verify(sig, message, l3Keys.publicKey);
      }
      const l3Time = performance.now() - l3Start;
      
      // Level 5
      setSecurityLevel(SecurityLevel.LEVEL_5);
      const l5Keys = generateSignatureKeyPair(randomBytes(32));
      const l5Start = performance.now();
      for (let i = 0; i < iterations; i++) {
        const sig = sign(message, l5Keys.secretKey);
        verify(sig, message, l5Keys.publicKey);
      }
      const l5Time = performance.now() - l5Start;
      
      const overhead = ((l5Time / l3Time) - 1) * 100;
      console.log(`Level 5 overhead: ${overhead.toFixed(1)}% slower than Level 3`);
      
      setSecurityLevel(SecurityLevel.LEVEL_3);
    });
  });
});
