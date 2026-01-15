import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from 'crypto';

const seed = new Uint8Array(randomBytes(32));
const keys = ml_dsa65.keygen(seed);
const msg = new TextEncoder().encode('test message');
const sig = ml_dsa65.sign(msg, keys.secretKey);

console.log('=== Finding correct verify() order ===');
console.log('msg:', msg.length, 'pk:', keys.publicKey.length, 'sig:', sig.length);

const orders = [
  ['publicKey', 'msg', 'sig', () => ml_dsa65.verify(keys.publicKey, msg, sig)],
  ['publicKey', 'sig', 'msg', () => ml_dsa65.verify(keys.publicKey, sig, msg)],
  ['msg', 'publicKey', 'sig', () => ml_dsa65.verify(msg, keys.publicKey, sig)],
  ['msg', 'sig', 'publicKey', () => ml_dsa65.verify(msg, sig, keys.publicKey)],
  ['sig', 'publicKey', 'msg', () => ml_dsa65.verify(sig, keys.publicKey, msg)],
  ['sig', 'msg', 'publicKey', () => ml_dsa65.verify(sig, msg, keys.publicKey)],
];

for (const [a, b, c, fn] of orders) {
  try {
    const result = fn();
    console.log(`✅ verify(${a}, ${b}, ${c}) = ${result}`);
  } catch(e) {
    console.log(`❌ verify(${a}, ${b}, ${c}): ${e.message.slice(0,50)}`);
  }
}
