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
 * NAMCHE Gateway Test Suite
 * 
 * Tests for the 7-gate mathematical verification flow.
 * Each gate is tested individually and in combination.
 * 
 * The 7 Gates:
 * 1. STRUCTURE_OK  - Valid DOKO format
 * 2. SIGNATURE_OK  - ML-DSA-65 signature verifies
 * 3. NODEID_OK     - NodeID matches two-part derivation
 * 4. TEMPORAL_OK   - Not expired, not from future
 * 5. NETWORK_OK    - Correct network name
 * 6. NOT_REVOKED   - Not in revocation log
 * 7. DOMAINS_OK    - Quorum verified domain claims
 * 
 * @module security/tests/namche-gateway.test.js
 * @version 1.0.0
 */

import { test, describe, before, beforeEach, after } from 'node:test';
import assert from 'node:assert';

import { 
  NamcheGateway, 
  DOKO_TYPES, 
  VERIFY_RESULT 
} from '../namche-gateway.js';

import { 
  generateKeyPair, 
  signMessage, 
  setCodebaseHash,
  generateNodeId,
} from '../../identity/node-key.js';

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

// Mock codebase hash for testing
const TEST_CODEBASE_HASH = 'a'.repeat(64);

// JSON Canonicalization helper (must match gateway implementation)
function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalize).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
}

/**
 * Create a valid DOKO for testing
 */
function createValidDoko(keyPair, nodeId, overrides = {}) {
  const now = Date.now();
  
  const doko = {
    version: '1.0',
    type: DOKO_TYPES.NODE_IDENTITY,
    nodeId: nodeId,
    publicKey: keyPair.publicKey,
    issuedAt: now,
    expiresAt: now + 86400000, // 24 hours
    networkName: 'yakmesh-mainnet',
    capabilities: {
      canVerifyDomains: true,
      canRouteNakpak: true,
      supportsKhata: true,
    },
    ...overrides,
  };

  // Sign the DOKO
  const payload = canonicalize(doko);
  const signature = signMessage(payload, keyPair.secretKey);
  doko.signature = signature;

  return doko;
}

describe('NAMCHE Gateway - 7-Gate Verification', () => {
  let gateway;
  let testKeyPair;
  let testNodeId;

  before(() => {
    // Set codebase hash for identity generation
    setCodebaseHash(TEST_CODEBASE_HASH);
  });

  beforeEach(() => {
    gateway = new NamcheGateway({ 
      networkName: 'yakmesh-mainnet',
      maxClockSkew: 60000, // 1 minute for tests
    });
    
    // Generate fresh keypair for each test
    testKeyPair = generateKeyPair();
    testNodeId = generateNodeId(hexToBytes(testKeyPair.publicKey));
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // GATE 1: STRUCTURE TESTS
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Gate 1: Structure Validation', () => {
    
    test('valid DOKO passes structure check', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      const result = await gateway.verify(doko);
      
      // Should pass at least structure check
      assert.ok(result.checks?.includes('STRUCTURE_OK') || result.valid);
    });

    test('missing version fails structure check', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      delete doko.version;
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.MALFORMED_STRUCTURE);
      assert.ok(result.detail.includes('version'));
    });

    test('missing type fails structure check', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      delete doko.type;
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.MALFORMED_STRUCTURE);
      assert.ok(result.detail.includes('type'));
    });

    test('missing nodeId fails structure check', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      delete doko.nodeId;
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.MALFORMED_STRUCTURE);
      assert.ok(result.detail.includes('nodeId'));
    });

    test('missing publicKey fails structure check', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      delete doko.publicKey;
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.MALFORMED_STRUCTURE);
      assert.ok(result.detail.includes('publicKey'));
    });

    test('missing signature fails structure check', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      delete doko.signature;
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.MALFORMED_STRUCTURE);
      assert.ok(result.detail.includes('signature'));
    });

    test('invalid type fails structure check', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId, { type: 'invalid-type' });
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.MALFORMED_STRUCTURE);
      assert.ok(result.detail.includes('type'));
    });

    test('non-numeric timestamps fail structure check', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId, { issuedAt: 'not-a-number' });
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.MALFORMED_STRUCTURE);
    });

    test('expiresAt before issuedAt fails structure check', async () => {
      const now = Date.now();
      const doko = createValidDoko(testKeyPair, testNodeId, { 
        issuedAt: now,
        expiresAt: now - 1000,
      });
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.MALFORMED_STRUCTURE);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // GATE 2: SIGNATURE TESTS
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Gate 2: Signature Validation', () => {
    
    test('valid signature passes', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      const result = await gateway.verify(doko);
      
      assert.ok(result.checks?.includes('SIGNATURE_OK') || result.valid);
    });

    test('tampered payload fails signature check', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      // Tamper with the payload AFTER signing
      doko.capabilities.canRouteNakpak = false;
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.INVALID_SIGNATURE);
    });

    test('wrong signature fails', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      // Create a different signature
      const otherKeyPair = generateKeyPair();
      const payload = canonicalize({ ...doko, signature: undefined });
      doko.signature = signMessage(payload, otherKeyPair.secretKey);
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.INVALID_SIGNATURE);
    });

    test('corrupted signature fails', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      // Corrupt the signature
      doko.signature = doko.signature.slice(0, -4) + 'ffff';
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.INVALID_SIGNATURE);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // GATE 3: NODEID TESTS
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Gate 3: NodeID Validation', () => {
    
    test('valid nodeId passes', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      const result = await gateway.verify(doko);
      
      assert.ok(result.checks?.includes('NODEID_OK') || result.valid);
    });

    test('nodeId without node- prefix fails', async () => {
      const doko = createValidDoko(testKeyPair, 'invalid-nodeid-format');
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.ok(result.reason === VERIFY_RESULT.NODEID_MISMATCH || 
                result.reason === VERIFY_RESULT.INVALID_SIGNATURE);
    });

    test('nodeId with wrong network fails', async () => {
      // Create a nodeId that looks valid but has wrong network
      const doko = createValidDoko(testKeyPair, 'node-wrong-network-xyz');
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      // Could fail at signature (wrong nodeId in payload) or nodeid check
    });

    test('nodeId too short fails', async () => {
      const doko = createValidDoko(testKeyPair, 'node-x');
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // GATE 4: TEMPORAL TESTS
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Gate 4: Temporal Validation', () => {
    
    test('valid temporal bounds pass', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      const result = await gateway.verify(doko);
      
      assert.ok(result.checks?.includes('TEMPORAL_OK') || result.valid);
    });

    test('expired DOKO fails', async () => {
      const past = Date.now() - 86400000; // 24 hours ago
      const doko = createValidDoko(testKeyPair, testNodeId, {
        issuedAt: past - 86400000,
        expiresAt: past,
      });
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.EXPIRED);
    });

    test('DOKO issued far in future fails', async () => {
      const future = Date.now() + 3600000; // 1 hour from now (beyond clock skew)
      const doko = createValidDoko(testKeyPair, testNodeId, {
        issuedAt: future,
        expiresAt: future + 86400000,
      });
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.ISSUED_IN_FUTURE);
    });

    test('DOKO within clock skew tolerance passes', async () => {
      // 30 seconds in future (within 60s tolerance)
      const slightly_future = Date.now() + 30000;
      const doko = createValidDoko(testKeyPair, testNodeId, {
        issuedAt: slightly_future,
        expiresAt: slightly_future + 86400000,
      });
      
      const result = await gateway.verify(doko);
      
      // Should not fail on temporal check
      assert.ok(result.reason !== VERIFY_RESULT.ISSUED_IN_FUTURE);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // GATE 5: NETWORK TESTS
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Gate 5: Network Validation', () => {
    
    test('matching network passes', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId, {
        networkName: 'yakmesh-mainnet',
      });
      const result = await gateway.verify(doko);
      
      assert.ok(result.checks?.includes('NETWORK_OK') || result.valid);
    });

    test('wrong network fails', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId, {
        networkName: 'yakmesh-testnet',
      });
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.WRONG_NETWORK);
    });

    test('missing networkName is allowed (optional field)', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      delete doko.networkName;
      // Re-sign without networkName
      const { signature, ...dokoWithoutSig } = doko;
      const payload = canonicalize(dokoWithoutSig);
      doko.signature = signMessage(payload, testKeyPair.secretKey);
      
      const result = await gateway.verify(doko);
      
      // Should not fail on network check
      assert.ok(result.reason !== VERIFY_RESULT.WRONG_NETWORK);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // GATE 6: REVOCATION TESTS
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Gate 6: Revocation Validation', () => {
    
    test('non-revoked DOKO passes', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      const result = await gateway.verify(doko);
      
      assert.ok(result.checks?.includes('NOT_REVOKED') || result.valid);
    });

    test('revoked DOKO fails', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      
      // First verify to get hash
      const result1 = await gateway.verify(doko);
      assert.ok(result1.valid);
      const dokoHash = result1.dokoHash;
      
      // Create and process revocation
      const revocation = {
        dokoHash,
        reason: 'key-compromise',
        revokedAt: Date.now(),
        revokedBy: doko.nodeId,
      };
      
      // Sign revocation
      const revokePayload = JSON.stringify({
        dokoHash: revocation.dokoHash,
        reason: revocation.reason,
        revokedAt: revocation.revokedAt,
        revokedBy: revocation.revokedBy,
      });
      revocation.signature = signMessage(revokePayload, testKeyPair.secretKey);
      
      await gateway.processRevocation(revocation, doko);
      
      // Now verification should fail
      const result2 = await gateway.verify(doko);
      
      assert.strictEqual(result2.valid, false);
      assert.strictEqual(result2.reason, VERIFY_RESULT.REVOKED);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // FULL VERIFICATION FLOW
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Full 7-Gate Verification', () => {
    
    test('valid DOKO passes all 7 gates', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.reason, VERIFY_RESULT.VALID);
      assert.ok(result.checks.includes('STRUCTURE_OK'));
      assert.ok(result.checks.includes('SIGNATURE_OK'));
      assert.ok(result.checks.includes('NODEID_OK'));
      assert.ok(result.checks.includes('TEMPORAL_OK'));
      assert.ok(result.checks.includes('NETWORK_OK'));
      assert.ok(result.checks.includes('NOT_REVOKED'));
    });

    test('verified DOKO is cached', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      
      const result = await gateway.verify(doko);
      assert.ok(result.valid);
      
      // Should be in cache
      const cached = gateway.lookupByHash(result.dokoHash);
      assert.ok(cached);
      assert.strictEqual(cached.nodeId, doko.nodeId);
    });

    test('gateway stats are updated', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      
      const statsBefore = gateway.getStats();
      assert.strictEqual(statsBefore.verificationsAttempted, 0);
      
      await gateway.verify(doko);
      
      const statsAfter = gateway.getStats();
      assert.strictEqual(statsAfter.verificationsAttempted, 1);
      assert.strictEqual(statsAfter.verificationsSucceeded, 1);
    });

    test('events are emitted on verification', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      
      let verified = false;
      gateway.on('verified', (data) => {
        verified = true;
        assert.strictEqual(data.doko.nodeId, doko.nodeId);
      });
      
      await gateway.verify(doko);
      assert.ok(verified);
    });

    test('events are emitted on failure', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      delete doko.version;
      
      let failed = false;
      gateway.on('verification-failed', (data) => {
        failed = true;
        assert.strictEqual(data.reason, VERIFY_RESULT.MALFORMED_STRUCTURE);
      });
      
      await gateway.verify(doko);
      assert.ok(failed);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // SECURITY ATTACK SCENARIOS
  // ═══════════════════════════════════════════════════════════════════════════

  describe('Security Attack Scenarios', () => {
    
    test('replay attack with expired DOKO fails', async () => {
      const past = Date.now() - 86400000;
      const doko = createValidDoko(testKeyPair, testNodeId, {
        issuedAt: past - 86400000,
        expiresAt: past,
      });
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.EXPIRED);
    });

    test('forged signature from different key fails', async () => {
      const doko = createValidDoko(testKeyPair, testNodeId);
      
      // Attacker generates their own keypair
      const attackerKeyPair = generateKeyPair();
      
      // Attacker tries to forge signature
      const { signature, ...dokoWithoutSig } = doko;
      const payload = canonicalize(dokoWithoutSig);
      doko.signature = signMessage(payload, attackerKeyPair.secretKey);
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.INVALID_SIGNATURE);
    });

    test('identity spoofing (wrong nodeId for key) fails', async () => {
      // Attacker tries to claim a different nodeId
      const attackerKeyPair = generateKeyPair();
      const victimNodeId = testNodeId; // Trying to impersonate
      
      const doko = createValidDoko(attackerKeyPair, victimNodeId);
      
      const result = await gateway.verify(doko);
      
      // Should fail because nodeId doesn't match attacker's publicKey derivation
      assert.strictEqual(result.valid, false);
    });

    test('network confusion attack fails', async () => {
      // Attacker creates valid DOKO but for wrong network
      const doko = createValidDoko(testKeyPair, testNodeId, {
        networkName: 'attacker-network',
      });
      
      const result = await gateway.verify(doko);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, VERIFY_RESULT.WRONG_NETWORK);
    });
  });
});

describe('NAMCHE Gateway - Utility Functions', () => {
  let gateway;

  beforeEach(() => {
    gateway = new NamcheGateway({ networkName: 'yakmesh-mainnet' });
  });

  test('computeDokoHash returns consistent hash', () => {
    setCodebaseHash(TEST_CODEBASE_HASH);
    const keyPair = generateKeyPair();
    const nodeId = generateNodeId(hexToBytes(keyPair.publicKey));
    const doko = createValidDoko(keyPair, nodeId);
    
    const hash1 = gateway.computeDokoHash(doko);
    const hash2 = gateway.computeDokoHash(doko);
    
    assert.strictEqual(hash1, hash2);
    assert.strictEqual(hash1.length, 64); // SHA3-256 = 32 bytes = 64 hex chars
  });

  test('getDokoPayload excludes signature', () => {
    setCodebaseHash(TEST_CODEBASE_HASH);
    const keyPair = generateKeyPair();
    const nodeId = generateNodeId(hexToBytes(keyPair.publicKey));
    const doko = createValidDoko(keyPair, nodeId);
    
    const payload = gateway.getDokoPayload(doko);
    
    assert.ok(!payload.includes('signature'));
    assert.ok(payload.includes('nodeId'));
    assert.ok(payload.includes('publicKey'));
  });
});
