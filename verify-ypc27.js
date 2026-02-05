/**
 * YPC-27 Quick Verification Script
 */

import { Poly27, YPC27Checksum, ypc27, bytesToTrits, tritsToBytes, N, DEFAULT_SEED } from './oracle/ypc27.js';

console.log('=== YPC-27 VERIFICATION ===\n');

// Test 1: Poly27 arithmetic
console.log('1. Poly27 Arithmetic:');
const x = new Poly27([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
const x2 = x.multiply(x);
console.log('   x * x = x^2 at index 2:', x2.get(2) === 1 ? '✓' : '✗');

// Test 2: Cyclic wrap (x^26 * x = x^27 = 1)
console.log('\n2. Cyclic Wrap (x^27 = 1):');
const x26 = new Poly27([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const wrap = x26.multiply(x);
console.log('   x^26 * x wraps to index 0:', wrap.get(0) === 1 ? '✓' : '✗');

// Test 3: Byte/Trit conversion round-trip
console.log('\n3. Byte ↔ Trit Conversion:');
const original = new Uint8Array([0, 42, 100, 200, 242]);
const trits = bytesToTrits(original);
const recovered = tritsToBytes(trits);
const roundTrip = Array.from(original).every((v, i) => v === recovered[i]);
console.log('   Round-trip [0, 42, 100, 200, 242]:', roundTrip ? '✓' : '✗');

// Test 4: Determinism
console.log('\n4. Checksum Determinism:');
const d1 = ypc27('deterministic test');
const d2 = ypc27('deterministic test');
console.log('   Same input → same output:', d1 === d2 ? '✓' : '✗');

// Test 5: Sensitivity
console.log('\n5. Input Sensitivity:');
const da = ypc27('message A');
const db = ypc27('message B');
console.log('   Different input → different output:', da !== db ? '✓' : '✗');

// Test 6: Avalanche effect
console.log('\n6. Avalanche Effect:');
const data1 = new Uint8Array([0, 0, 0, 0, 0]);
const data2 = new Uint8Array([1, 0, 0, 0, 0]);
const c1 = YPC27Checksum.compute(data1);
const c2 = YPC27Checksum.compute(data2);
let diffCount = 0;
for (let i = 0; i < N; i++) {
  if (c1.get(i) !== c2.get(i)) diffCount++;
}
console.log(`   Single bit flip affects ${diffCount}/${N} coefficients:`, diffCount > 10 ? '✓' : '✗');

// Test 7: Verify function
console.log('\n7. Verify Function:');
const testData = 'verify this packet';
const checksum = YPC27Checksum.compute(testData);
const valid = YPC27Checksum.verify(testData, checksum);
const invalid = YPC27Checksum.verify('tampered packet', checksum);
console.log('   Valid data passes:', valid ? '✓' : '✗');
console.log('   Tampered data fails:', !invalid ? '✓' : '✗');

console.log('\n=== YPC-27 VERIFICATION COMPLETE ===');
