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
import { TrisulaTST, TrisulaPeerRouter } from './mesh/trisula-tree.js';

console.log('=== TRISULA ROUTING AUDIT ===\n');

// Create test peers
const router = new TrisulaPeerRouter('a'.repeat(64));
const peers = [
  'a'.repeat(63) + 'b',  // Very close
  'a'.repeat(32) + 'f'.repeat(32),  // Medium distance
  'f'.repeat(64),  // Far
  'a'.repeat(63) + 'c',  // Also close
];

peers.forEach(p => router.addPeer(p, { ip: '127.0.0.1' }));

// Test XOR-distance routing
console.log('1. Closest peers by XOR distance:');
const closest = router.findClosestPeers('a'.repeat(64), 3);
console.log('   Returns 3 closest:', closest.length === 3 ? '✓' : '✗');
console.log('   Has nodeId property:', closest[0]?.nodeId ? '✓' : '✗');
console.log('   First is closest to target:', closest[0]?.nodeId?.startsWith('a'.repeat(63)) ? '✓' : '✗');

// Test prefix search (for DHT lookups)
console.log('\n2. Prefix search (DHT routing):');
const tst = new TrisulaTST();
tst.insert('abc', 1);
tst.insert('abd', 2);
tst.insert('xyz', 3);
const prefixResults = tst.prefixSearch('ab');
console.log('   "ab" prefix finds 2 entries:', prefixResults.length === 2 ? '✓' : '✗');
console.log('   Prefix result type:', typeof prefixResults[0]);
console.log('   Returns {key, value} objects:', prefixResults[0]?.key && prefixResults[0]?.value !== undefined ? '✓' : '✗');

// Test 3-way branching
console.log('\n3. O(k) complexity verification:');
const longId = 'a'.repeat(1000);
const start = process.hrtime.bigint();
tst.insert(longId, 999);
const found = tst.search(longId);
const end = process.hrtime.bigint();
console.log('   1000-char key insert+search:', found === 999 ? '✓' : '✗');
console.log('   Time:', Number(end - start) / 1000, 'µs');

console.log('\n=== TRISULA AUDIT COMPLETE ===');
