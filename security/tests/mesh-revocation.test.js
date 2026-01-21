/**
 * Mesh Revocation Tests
 * 
 * Tests for mathematical threshold-based revocation.
 * No voting, no periods - just math.
 * 
 * @module security/tests/mesh-revocation.test.js
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import {
  MeshRevocation,
  Attestation,
  RevocationState,
  REVOCATION_REASONS,
  MESH_REVOCATION_MESSAGES,
} from '../mesh-revocation.js';

// Generate test keypairs
function generateKeypair() {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const { publicKey, secretKey } = ml_dsa65.keygen(seed);
  return { publicKey: bytesToHex(publicKey), privateKey: secretKey };
}

// Create a test DOKO ID
function createDokoId(prefix = 'test') {
  const id = bytesToHex(crypto.getRandomValues(new Uint8Array(8)));
  return `doko-node-${prefix}-${id}`;
}

describe('Attestation', () => {
  let keypair;
  let dokoId;
  let attesterId;

  beforeEach(() => {
    keypair = generateKeypair();
    dokoId = createDokoId('target');
    attesterId = createDokoId('attester');
  });

  it('should create attestation with required fields', () => {
    const attestation = new Attestation({
      dokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId,
    });

    expect(attestation.dokoId).toBe(dokoId);
    expect(attestation.reason).toBe(REVOCATION_REASONS.DOUBLE_SIGN);
    expect(attestation.attesterId).toBe(attesterId);
    expect(attestation.version).toBe('1.0');
    expect(attestation.timestamp).toBeTruthy();
  });

  it('should generate unique ID', () => {
    const a1 = new Attestation({ dokoId, reason: REVOCATION_REASONS.DOUBLE_SIGN, attesterId });
    const a2 = new Attestation({ dokoId, reason: REVOCATION_REASONS.DOUBLE_SIGN, attesterId: createDokoId() });
    
    expect(a1.getId()).not.toBe(a2.getId());
  });

  it('should sign attestation', () => {
    const attestation = new Attestation({
      dokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId,
    });

    attestation.sign(keypair.privateKey);
    
    expect(attestation.signature).toBeTruthy();
    expect(typeof attestation.signature).toBe('string');
  });

  it('should verify valid signature', () => {
    const attestation = new Attestation({
      dokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId,
    });

    attestation.sign(keypair.privateKey);
    
    expect(attestation.verify(keypair.publicKey)).toBe(true);
  });

  it('should reject invalid signature', () => {
    const attestation = new Attestation({
      dokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId,
    });

    attestation.sign(keypair.privateKey);
    
    // Use different keypair
    const otherKeypair = generateKeypair();
    expect(attestation.verify(otherKeypair.publicKey)).toBe(false);
  });

  it('should detect tampering', () => {
    const attestation = new Attestation({
      dokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId,
    });

    attestation.sign(keypair.privateKey);
    
    // Tamper with data
    attestation.reason = REVOCATION_REASONS.KEY_REUSE;
    
    expect(attestation.verify(keypair.publicKey)).toBe(false);
  });

  it('should check expiration', () => {
    const attestation = new Attestation({
      dokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId,
      timestamp: Date.now() - (8 * 24 * 60 * 60 * 1000), // 8 days ago
    });

    expect(attestation.isExpired()).toBe(true);
  });

  it('should not be expired for recent attestation', () => {
    const attestation = new Attestation({
      dokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId,
    });

    expect(attestation.isExpired()).toBe(false);
  });

  it('should serialize to JSON', () => {
    const attestation = new Attestation({
      dokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId,
    });
    attestation.sign(keypair.privateKey);

    const json = attestation.toJSON();
    
    expect(json.dokoId).toBe(dokoId);
    expect(json.reason).toBe(REVOCATION_REASONS.DOUBLE_SIGN);
    expect(json.signature).toBeTruthy();
  });

  it('should deserialize from JSON', () => {
    const attestation = new Attestation({
      dokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId,
    });
    attestation.sign(keypair.privateKey);

    const json = attestation.toJSON();
    const restored = Attestation.fromJSON(json);
    
    expect(restored.dokoId).toBe(attestation.dokoId);
    expect(restored.reason).toBe(attestation.reason);
    expect(restored.verify(keypair.publicKey)).toBe(true);
  });
});

describe('RevocationState', () => {
  let dokoId;
  let keypairs;
  let attesterIds;

  beforeEach(() => {
    dokoId = createDokoId('target');
    keypairs = Array.from({ length: 5 }, () => generateKeypair());
    attesterIds = Array.from({ length: 5 }, (_, i) => createDokoId(`attester-${i}`));
  });

  function createSignedAttestation(index, reason = REVOCATION_REASONS.DOUBLE_SIGN) {
    const attestation = new Attestation({
      dokoId,
      reason,
      attesterId: attesterIds[index],
    });
    attestation.sign(keypairs[index].privateKey);
    return attestation;
  }

  it('should create empty state', () => {
    const state = new RevocationState(dokoId);
    
    expect(state.dokoId).toBe(dokoId);
    expect(state.count).toBe(0);
  });

  it('should add attestation', () => {
    const state = new RevocationState(dokoId);
    const attestation = createSignedAttestation(0);
    
    const added = state.addAttestation(attestation);
    
    expect(added).toBe(true);
    expect(state.count).toBe(1);
  });

  it('should reject duplicate attestation from same attester', () => {
    const state = new RevocationState(dokoId);
    const a1 = createSignedAttestation(0);
    
    state.addAttestation(a1);
    
    // Try to add another from same attester (older timestamp)
    const a2 = new Attestation({
      dokoId,
      reason: REVOCATION_REASONS.KEY_REUSE,
      attesterId: attesterIds[0],
      timestamp: Date.now() - 1000, // Older
    });
    a2.sign(keypairs[0].privateKey);
    
    const added = state.addAttestation(a2);
    
    expect(added).toBe(false);
    expect(state.count).toBe(1);
  });

  it('should update attestation if newer from same attester', () => {
    const state = new RevocationState(dokoId);
    
    const a1 = new Attestation({
      dokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId: attesterIds[0],
      timestamp: Date.now() - 1000,
    });
    a1.sign(keypairs[0].privateKey);
    state.addAttestation(a1);
    
    // Add newer from same attester
    const a2 = createSignedAttestation(0, REVOCATION_REASONS.KEY_REUSE);
    const added = state.addAttestation(a2);
    
    expect(added).toBe(true);
    expect(state.count).toBe(1);
    expect(state.primaryReason).toBe(REVOCATION_REASONS.KEY_REUSE);
  });

  it('should track reason counts', () => {
    const state = new RevocationState(dokoId);
    
    state.addAttestation(createSignedAttestation(0, REVOCATION_REASONS.DOUBLE_SIGN));
    state.addAttestation(createSignedAttestation(1, REVOCATION_REASONS.DOUBLE_SIGN));
    state.addAttestation(createSignedAttestation(2, REVOCATION_REASONS.KEY_REUSE));
    
    expect(state.reasons.get(REVOCATION_REASONS.DOUBLE_SIGN)).toBe(2);
    expect(state.reasons.get(REVOCATION_REASONS.KEY_REUSE)).toBe(1);
    expect(state.primaryReason).toBe(REVOCATION_REASONS.DOUBLE_SIGN);
  });

  it('should determine revocation at 2/3 threshold', () => {
    const state = new RevocationState(dokoId);
    
    // 3 nodes active, need 2 attestations (ceil(3 * 2/3) = 2)
    state.addAttestation(createSignedAttestation(0));
    
    let result = state.isRevoked(3);
    expect(result.revoked).toBe(false);
    expect(result.progress).toBe(0.5);
    
    state.addAttestation(createSignedAttestation(1));
    
    result = state.isRevoked(3);
    expect(result.revoked).toBe(true);
    expect(result.attestationCount).toBe(2);
    expect(result.threshold).toBe(2);
  });

  it('should handle larger network thresholds', () => {
    const state = new RevocationState(dokoId);
    
    // 10 nodes active, need 7 attestations (ceil(10 * 2/3) = 7)
    for (let i = 0; i < 5; i++) {
      state.addAttestation(createSignedAttestation(i));
    }
    
    // Create more attesters
    for (let i = 5; i < 7; i++) {
      const kp = generateKeypair();
      const att = new Attestation({
        dokoId,
        reason: REVOCATION_REASONS.DOUBLE_SIGN,
        attesterId: createDokoId(`extra-${i}`),
      });
      att.sign(kp.privateKey);
      state.addAttestation(att);
    }
    
    const result = state.isRevoked(10);
    expect(result.revoked).toBe(true);
    expect(result.threshold).toBe(7);
  });

  it('should reject revocation if network too small', () => {
    const state = new RevocationState(dokoId);
    state.addAttestation(createSignedAttestation(0));
    state.addAttestation(createSignedAttestation(1));
    
    const result = state.isRevoked(2, { minNodes: 3, threshold: 2/3 });
    
    expect(result.revoked).toBe(false);
    expect(result.reason).toBe('INSUFFICIENT_NETWORK');
  });

  it('should prune expired attestations', () => {
    const state = new RevocationState(dokoId);
    
    // Add old attestation
    const oldAtt = new Attestation({
      dokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId: attesterIds[0],
      timestamp: Date.now() - (8 * 24 * 60 * 60 * 1000), // 8 days ago
    });
    oldAtt.sign(keypairs[0].privateKey);
    state.addAttestation(oldAtt);
    
    // Add fresh attestation
    state.addAttestation(createSignedAttestation(1));
    
    expect(state.count).toBe(2);
    
    const pruned = state.pruneExpired();
    
    expect(pruned).toBe(1);
    expect(state.count).toBe(1);
  });

  it('should export attestations', () => {
    const state = new RevocationState(dokoId);
    state.addAttestation(createSignedAttestation(0));
    state.addAttestation(createSignedAttestation(1));
    
    const exported = state.export();
    
    expect(exported.length).toBe(2);
    expect(exported[0].signature).toBeTruthy();
  });
});

describe('MeshRevocation', () => {
  let revocation;
  let nodeKeypair;
  let nodeDokoId;
  let targetDokoId;
  let publicKeyMap;

  beforeEach(() => {
    nodeKeypair = generateKeypair();
    nodeDokoId = createDokoId('mynode');
    targetDokoId = createDokoId('target');
    publicKeyMap = new Map();
    publicKeyMap.set(nodeDokoId, nodeKeypair.publicKey);

    revocation = new MeshRevocation({
      myDokoId: nodeDokoId,
      privateKey: nodeKeypair.privateKey,
      resolvePublicKey: (id) => publicKeyMap.get(id),
      getActiveNodeCount: () => 10,
    });
  });

  it('should create attestation', () => {
    const attestation = revocation.createAttestation(
      targetDokoId,
      REVOCATION_REASONS.DOUBLE_SIGN
    );

    expect(attestation).toBeTruthy();
    expect(attestation.dokoId).toBe(targetDokoId);
    expect(attestation.attesterId).toBe(nodeDokoId);
    expect(attestation.signature).toBeTruthy();
  });

  it('should reject invalid reason', () => {
    expect(() => {
      revocation.createAttestation(targetDokoId, 'invalid_reason');
    
    }).toThrow(/Invalid reason/);
  });

  it('should add attestation from another node', () => {
    // Create attestation from a different node
    const otherKeypair = generateKeypair();
    const otherDokoId = createDokoId('other');
    publicKeyMap.set(otherDokoId, otherKeypair.publicKey);

    const attestation = new Attestation({
      dokoId: targetDokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId: otherDokoId,
    });
    attestation.sign(otherKeypair.privateKey);

    const result = revocation.addAttestation(attestation);
    
    expect(result.accepted).toBe(true);
  });

  it('should reject expired attestation', () => {
    const attestation = new Attestation({
      dokoId: targetDokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId: nodeDokoId,
      timestamp: Date.now() - (8 * 24 * 60 * 60 * 1000),
    });
    attestation.sign(nodeKeypair.privateKey);

    const result = revocation.addAttestation(attestation);
    
    expect(result.accepted).toBe(false);
    expect(result.error).toBe('EXPIRED');
  });

  it('should reject attestation from unknown attester', () => {
    const unknownKeypair = generateKeypair();
    const attestation = new Attestation({
      dokoId: targetDokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId: 'doko-unknown-xyz',
    });
    attestation.sign(unknownKeypair.privateKey);

    const result = revocation.addAttestation(attestation);
    
    expect(result.accepted).toBe(false);
    expect(result.error).toBe('UNKNOWN_ATTESTER');
  });

  it('should reject attestation with invalid signature', () => {
    const attestation = new Attestation({
      dokoId: targetDokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId: nodeDokoId,
    });
    // Sign with wrong key
    const wrongKeypair = generateKeypair();
    attestation.sign(wrongKeypair.privateKey);

    const result = revocation.addAttestation(attestation);
    
    expect(result.accepted).toBe(false);
    expect(result.error).toBe('INVALID_SIGNATURE');
  });

  it('should check revocation status', () => {
    // Not enough attestations
    let status = revocation.isRevoked(targetDokoId);
    expect(status.revoked).toBe(false);
    expect(status.reason).toBe('NO_ATTESTATIONS');

    // Add attestation
    revocation.createAttestation(targetDokoId, REVOCATION_REASONS.DOUBLE_SIGN);
    
    status = revocation.isRevoked(targetDokoId);
    expect(status.revoked).toBe(false);
    expect(status.reason).toBe('BELOW_THRESHOLD');
  });

  it('should revoke when threshold met', () => {
    // Create 10 attesters
    const attesters = [];
    for (let i = 0; i < 10; i++) {
      const kp = generateKeypair();
      const id = createDokoId(`attester-${i}`);
      publicKeyMap.set(id, kp.publicKey);
      attesters.push({ keypair: kp, dokoId: id });
    }

    // Add 7 attestations (threshold for 10 nodes = ceil(10 * 2/3) = 7)
    for (let i = 0; i < 7; i++) {
      const att = new Attestation({
        dokoId: targetDokoId,
        reason: REVOCATION_REASONS.DOUBLE_SIGN,
        attesterId: attesters[i].dokoId,
      });
      att.sign(attesters[i].keypair.privateKey);
      revocation.addAttestation(att);
    }

    const status = revocation.isRevoked(targetDokoId);
    
    expect(status.revoked).toBe(true);
    expect(status.attestationCount).toBe(7);
    expect(status.threshold).toBe(7);
    expect(status.confidence).toBe(0.7);
  });

  it('should emit revoked event when threshold met', async () => {
    const attesters = [];
    for (let i = 0; i < 7; i++) {
      const kp = generateKeypair();
      const id = createDokoId(`attester-${i}`);
      publicKeyMap.set(id, kp.publicKey);
      attesters.push({ keypair: kp, dokoId: id });
    }

    let revokedEvent = null;
    revocation.on('revoked', (event) => {
      revokedEvent = event;
    });

    // Add attestations
    for (let i = 0; i < 7; i++) {
      const att = new Attestation({
        dokoId: targetDokoId,
        reason: REVOCATION_REASONS.DOUBLE_SIGN,
        attesterId: attesters[i].dokoId,
      });
      att.sign(attesters[i].keypair.privateKey);
      revocation.addAttestation(att);
    }

    expect(revokedEvent).toBeTruthy();
    expect(revokedEvent.dokoId).toBe(targetDokoId);
    expect(revokedEvent.revoked).toBe(true);
  });

  it('should create revocation certificate', () => {
    const attesters = [];
    for (let i = 0; i < 7; i++) {
      const kp = generateKeypair();
      const id = createDokoId(`attester-${i}`);
      publicKeyMap.set(id, kp.publicKey);
      attesters.push({ keypair: kp, dokoId: id });

      const att = new Attestation({
        dokoId: targetDokoId,
        reason: REVOCATION_REASONS.DOUBLE_SIGN,
        attesterId: id,
      });
      att.sign(kp.privateKey);
      revocation.addAttestation(att);
    }

    const cert = revocation.createRevocationCertificate(targetDokoId);
    
    expect(cert).toBeTruthy();
    expect(cert.type).toBe('mesh-consensus');
    expect(cert.dokoId).toBe(targetDokoId);
    expect(cert.attestationCount).toBe(7);
    expect(cert.attestations.length).toBe(7);
  });

  it('should verify revocation certificate', () => {
    const attesters = [];
    for (let i = 0; i < 7; i++) {
      const kp = generateKeypair();
      const id = createDokoId(`attester-${i}`);
      publicKeyMap.set(id, kp.publicKey);
      attesters.push({ keypair: kp, dokoId: id });

      const att = new Attestation({
        dokoId: targetDokoId,
        reason: REVOCATION_REASONS.DOUBLE_SIGN,
        attesterId: id,
      });
      att.sign(kp.privateKey);
      revocation.addAttestation(att);
    }

    const cert = revocation.createRevocationCertificate(targetDokoId);
    const verification = MeshRevocation.verifyCertificate(cert, (id) => publicKeyMap.get(id));
    
    expect(verification.valid).toBe(true);
    expect(verification.validSignatures).toBe(7);
  });

  it('should reject certificate with invalid threshold', () => {
    const cert = {
      version: '1.0',
      type: 'mesh-consensus',
      dokoId: targetDokoId,
      activeNodes: 10,
      threshold: 5, // Should be 7
      attestations: [],
    };

    const verification = MeshRevocation.verifyCertificate(cert, () => null);
    
    expect(verification.valid).toBe(false);
    expect(verification.reason).toBe('INVALID_THRESHOLD');
  });

  it('should reject certificate below threshold', () => {
    const attesters = [];
    for (let i = 0; i < 5; i++) {
      const kp = generateKeypair();
      const id = createDokoId(`attester-${i}`);
      publicKeyMap.set(id, kp.publicKey);
      attesters.push({ keypair: kp, dokoId: id });
    }

    const attestations = attesters.map((a, i) => {
      const att = new Attestation({
        dokoId: targetDokoId,
        reason: REVOCATION_REASONS.DOUBLE_SIGN,
        attesterId: a.dokoId,
      });
      att.sign(a.keypair.privateKey);
      return att.toJSON();
    });

    const cert = {
      version: '1.0',
      type: 'mesh-consensus',
      dokoId: targetDokoId,
      activeNodes: 10,
      threshold: 7,
      attestations,
    };

    const verification = MeshRevocation.verifyCertificate(cert, (id) => publicKeyMap.get(id));
    
    expect(verification.valid).toBe(false);
    expect(verification.reason).toBe('BELOW_THRESHOLD');
  });

  it('should import and export attestations', () => {
    // Create some attestations
    const attesters = [];
    for (let i = 0; i < 3; i++) {
      const kp = generateKeypair();
      const id = createDokoId(`attester-${i}`);
      publicKeyMap.set(id, kp.publicKey);
      
      const att = new Attestation({
        dokoId: targetDokoId,
        reason: REVOCATION_REASONS.DOUBLE_SIGN,
        attesterId: id,
      });
      att.sign(kp.privateKey);
      revocation.addAttestation(att);
    }

    const exported = revocation.exportAttestations();
    expect(exported.length).toBe(3);

    // Create new instance and import
    const revocation2 = new MeshRevocation({
      resolvePublicKey: (id) => publicKeyMap.get(id),
      getActiveNodeCount: () => 10,
    });

    const result = revocation2.importAttestations(exported);
    expect(result.imported).toBe(3);
    expect(result.failed).toBe(0);
  });

  it('should get statistics', () => {
    const attesters = [];
    for (let i = 0; i < 3; i++) {
      const kp = generateKeypair();
      const id = createDokoId(`attester-${i}`);
      publicKeyMap.set(id, kp.publicKey);
      
      const att = new Attestation({
        dokoId: targetDokoId,
        reason: REVOCATION_REASONS.DOUBLE_SIGN,
        attesterId: id,
      });
      att.sign(kp.privateKey);
      revocation.addAttestation(att);
    }

    const stats = revocation.getStats();
    
    expect(stats.trackedDokos).toBe(1);
    expect(stats.totalAttestations).toBe(3);
    expect(stats.activeNodes).toBe(10);
    expect(stats.byReason[REVOCATION_REASONS.DOUBLE_SIGN]).toBe(3);
  });

  it('should prune expired attestations', () => {
    // Add old attestation
    const oldAtt = new Attestation({
      dokoId: targetDokoId,
      reason: REVOCATION_REASONS.DOUBLE_SIGN,
      attesterId: nodeDokoId,
      timestamp: Date.now() - (8 * 24 * 60 * 60 * 1000),
    });
    oldAtt.sign(nodeKeypair.privateKey);
    
    // Manually add to state (bypass validation)
    const state = new RevocationState(targetDokoId);
    state.addAttestation(oldAtt);
    revocation.states.set(targetDokoId, state);

    expect(revocation.getStats().totalAttestations).toBe(1);
    
    revocation.pruneExpired();
    
    expect(revocation.getStats().totalAttestations).toBe(0);
    expect(revocation.getStats().trackedDokos).toBe(0);
  });
});

describe('MESH_REVOCATION_MESSAGES', () => {
  it('should have all message types', () => {
    expect(MESH_REVOCATION_MESSAGES.ATTESTATION).toBeTruthy();
    expect(MESH_REVOCATION_MESSAGES.ATTESTATIONS_SYNC).toBeTruthy();
    expect(MESH_REVOCATION_MESSAGES.REVOCATION_CERT).toBeTruthy();
  });
});

describe('Edge Cases', () => {
  it('should handle 3-node minimum network', () => {
    const state = new RevocationState(createDokoId());
    
    // Add 2 attestations
    for (let i = 0; i < 2; i++) {
      const kp = generateKeypair();
      const att = new Attestation({
        dokoId: state.dokoId,
        reason: REVOCATION_REASONS.DOUBLE_SIGN,
        attesterId: createDokoId(`att-${i}`),
      });
      att.sign(kp.privateKey);
      state.addAttestation(att);
    }

    // 3 nodes, need ceil(3 * 2/3) = 2
    const result = state.isRevoked(3);
    expect(result.revoked).toBe(true);
  });

  it('should handle exactly 2/3 threshold', () => {
    const state = new RevocationState(createDokoId());
    
    // 6 nodes, need ceil(6 * 2/3) = 4
    for (let i = 0; i < 4; i++) {
      const kp = generateKeypair();
      const att = new Attestation({
        dokoId: state.dokoId,
        reason: REVOCATION_REASONS.DOUBLE_SIGN,
        attesterId: createDokoId(`att-${i}`),
      });
      att.sign(kp.privateKey);
      state.addAttestation(att);
    }

    const result = state.isRevoked(6);
    expect(result.revoked).toBe(true);
    expect(result.threshold).toBe(4);
  });

  it('should handle network size changes', () => {
    const state = new RevocationState(createDokoId());
    
    // Add 5 attestations
    for (let i = 0; i < 5; i++) {
      const kp = generateKeypair();
      const att = new Attestation({
        dokoId: state.dokoId,
        reason: REVOCATION_REASONS.DOUBLE_SIGN,
        attesterId: createDokoId(`att-${i}`),
      });
      att.sign(kp.privateKey);
      state.addAttestation(att);
    }

    // With 6 nodes (threshold 4): revoked
    let result = state.isRevoked(6);
    expect(result.revoked).toBe(true);

    // With 10 nodes (threshold 7): NOT revoked
    result = state.isRevoked(10);
    expect(result.revoked).toBe(false);
    expect(result.progress).toBe(5/7);
  });

  it('should handle multiple targets simultaneously', () => {
    const revocation = new MeshRevocation({
      resolvePublicKey: () => null, // We'll skip verification
      getActiveNodeCount: () => 3,
    });

    const target1 = createDokoId('target1');
    const target2 = createDokoId('target2');

    // Manually add states
    const state1 = new RevocationState(target1);
    const state2 = new RevocationState(target2);

    for (let i = 0; i < 2; i++) {
      const kp = generateKeypair();
      const att1 = new Attestation({
        dokoId: target1,
        reason: REVOCATION_REASONS.DOUBLE_SIGN,
        attesterId: createDokoId(`att1-${i}`),
      });
      att1.sign(kp.privateKey);
      state1.addAttestation(att1);
    }

    // Only 1 attestation for target2
    const kp = generateKeypair();
    const att2 = new Attestation({
      dokoId: target2,
      reason: REVOCATION_REASONS.KEY_REUSE,
      attesterId: createDokoId('att2'),
    });
    att2.sign(kp.privateKey);
    state2.addAttestation(att2);

    revocation.states.set(target1, state1);
    revocation.states.set(target2, state2);

    expect(revocation.isRevoked(target1).revoked).toBe(true);
    expect(revocation.isRevoked(target2).revoked).toBe(false);
  });
});
