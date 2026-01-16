/**
 * Identity Audit Test
 * Checks if node IDs are properly using iO obfuscation
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

// Check the current node identity
const keyPath = './data/node-key.json';

console.log('=== YAKMESH Identity Audit ===\n');

if (existsSync(keyPath)) {
  const identity = JSON.parse(readFileSync(keyPath, 'utf8'));
  
  console.log('Current Identity:');
  console.log(`  Node ID: ${identity.nodeId}`);
  console.log(`  Algorithm: ${identity.algorithm}`);
  console.log('');
  
  // Check if it's using raw hash format
  if (identity.nodeId.startsWith('lantern_')) {
    console.log('⚠️  ISSUE: Node ID uses raw "lantern_" + hex hash format');
    console.log('   This exposes the raw hash instead of using iO obfuscation');
    console.log('');
    console.log('   Expected: iO-derived name like "qubit-lattice-prism" or "pq-a7x9"');
    console.log('   Got: ' + identity.nodeId);
  } else {
    console.log('✓ Node ID appears to use iO-style naming');
  }
} else {
  console.log('No node identity found at ' + keyPath);
}

// Now check what the network-identity module would generate
console.log('\n--- Testing iO Network Identity ---\n');

try {
  const { deriveNetworkName, deriveNetworkId } = await import('./oracle/network-identity.js');
  
  // Use a sample hash
  const sampleHash = '80d75d2c3e00ce7d1234567890abcdef1234567890abcdef1234567890abcdef';
  
  const networkName = deriveNetworkName(sampleHash);
  const networkId = deriveNetworkId(sampleHash);
  
  console.log('iO-derived values from sample hash:');
  console.log(`  Network Name: ${networkName}`);
  console.log(`  Network ID: ${networkId}`);
  console.log('');
  console.log('✓ iO obfuscation is working - but NOT being used for node IDs!');
  
} catch (e) {
  console.error('Error importing network-identity:', e.message);
}

console.log('\n--- Recommendations ---\n');
console.log('1. Modify identity/node-key.js to use deriveNetworkName() for nodeId');
console.log('2. Replace "lantern_" + hex hash with iO-derived name');
console.log('3. The internal identity can still store the hash, but external ID should be obfuscated');
