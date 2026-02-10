/**
 * GUMBA Protocol Tests
 * 
 * Testing the Guarded Universal Message Bundle Access system
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { randomBytes } from 'crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex } from '@noble/hashes/utils.js';

import {
  GumbaKey,
  GumbaMemberTree,
  GumbaProof,
  GumbaGate,
  GumbaBundle,
  GumbaHub,
  GUMBA_CONFIG,
  GUMBA_PROOF_TYPE,
  GUMBA_ROLE,
} from '../gumba.js';

// ═══════════════════════════════════════════════════════════════════════════════
// TEST HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function createTestIdentity(name) {
  // Create a proper Uint8Array seed for ML-DSA-65
  const seed = new Uint8Array(32);
  const seedBuffer = randomBytes(32);
  seed.set(seedBuffer);
  
  const keyPair = ml_dsa65.keygen(seed);
  
  return {
    dokoId: `doko-${name}-${bytesToHex(randomBytes(8))}`,
    name,
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
    nodeId: `node-${name}-${bytesToHex(randomBytes(8))}`,
  };
}

function createMockMesh() {
  return {
    peers: new Map(),
    sendTo: () => {},
    on: () => {},
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// GUMBA KEY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('GumbaKey', () => {
  it('derives deterministic key from owner secret', () => {
    const secret = randomBytes(32);
    const bundleId = 'test-bundle-1';
    
    const key1 = new GumbaKey(bundleId, secret);
    const key2 = new GumbaKey(bundleId, secret);
    
    // Same inputs = same key
    assert.deepStrictEqual(key1.key, key2.key);
  });
  
  it('derives different keys for different bundles', () => {
    const secret = randomBytes(32);
    
    const key1 = new GumbaKey('bundle-a', secret);
    const key2 = new GumbaKey('bundle-b', secret);
    
    assert.notDeepStrictEqual(key1.key, key2.key);
  });
  
  it('derives different keys for different owners', () => {
    const bundleId = 'test-bundle';
    
    const key1 = new GumbaKey(bundleId, randomBytes(32));
    const key2 = new GumbaKey(bundleId, randomBytes(32));
    
    assert.notDeepStrictEqual(key1.key, key2.key);
  });
  
  it('seals and unseals content correctly', () => {
    const key = new GumbaKey('test-bundle', randomBytes(32));
    const plaintext = { message: 'Hello GUMBA!', timestamp: Date.now() };
    
    const sealed = key.seal(plaintext);
    
    assert.ok(sealed.nonce);
    assert.ok(sealed.ciphertext);
    assert.ok(sealed.authTag);
    assert.ok(sealed.aad);
    
    const unsealed = key.unseal(sealed);
    const parsed = JSON.parse(unsealed);
    
    assert.strictEqual(parsed.message, plaintext.message);
  });
  
  it('tracks message count for rotation', () => {
    const key = new GumbaKey('test-bundle', randomBytes(32));
    
    assert.strictEqual(key.messageCount, 0);
    assert.strictEqual(key.needsRotation(), false);
    
    key.seal('test');
    assert.strictEqual(key.messageCount, 1);
  });
  
  it('destroys key material securely', () => {
    const key = new GumbaKey('test-bundle', randomBytes(32));
    
    assert.ok(key.key);
    key.destroy();
    assert.strictEqual(key.key, null);
  });
  
  it('fails to unseal with wrong key', () => {
    const key1 = new GumbaKey('bundle', randomBytes(32));
    const key2 = new GumbaKey('bundle', randomBytes(32));
    
    const sealed = key1.seal('secret message');
    
    assert.throws(() => {
      key2.unseal(sealed);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// MEMBER TREE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('GumbaMemberTree', () => {
  let tree;
  
  beforeEach(() => {
    tree = new GumbaMemberTree();
  });
  
  it('adds and checks members', () => {
    const dokoId = 'doko-test-123';
    
    assert.strictEqual(tree.isMember(dokoId), false);
    
    tree.addMember(dokoId, GUMBA_ROLE.MEMBER);
    
    assert.strictEqual(tree.isMember(dokoId), true);
    assert.strictEqual(tree.size, 1);
  });
  
  it('removes members', () => {
    const dokoId = 'doko-test-123';
    tree.addMember(dokoId, GUMBA_ROLE.MEMBER);
    
    assert.strictEqual(tree.isMember(dokoId), true);
    
    tree.removeMember(dokoId);
    
    assert.strictEqual(tree.isMember(dokoId), false);
    assert.strictEqual(tree.size, 0);
  });
  
  it('tracks member roles', () => {
    tree.addMember('owner-1', GUMBA_ROLE.OWNER);
    tree.addMember('admin-1', GUMBA_ROLE.ADMIN);
    tree.addMember('member-1', GUMBA_ROLE.MEMBER);
    tree.addMember('reader-1', GUMBA_ROLE.READER);
    
    assert.strictEqual(tree.getRole('owner-1'), GUMBA_ROLE.OWNER);
    assert.strictEqual(tree.getRole('admin-1'), GUMBA_ROLE.ADMIN);
    assert.strictEqual(tree.getRole('member-1'), GUMBA_ROLE.MEMBER);
    assert.strictEqual(tree.getRole('reader-1'), GUMBA_ROLE.READER);
  });
  
  it('checks role hierarchy correctly', () => {
    tree.addMember('owner-1', GUMBA_ROLE.OWNER);
    tree.addMember('reader-1', GUMBA_ROLE.READER);
    
    // Owner has all roles
    assert.strictEqual(tree.hasRole('owner-1', GUMBA_ROLE.READER), true);
    assert.strictEqual(tree.hasRole('owner-1', GUMBA_ROLE.MEMBER), true);
    assert.strictEqual(tree.hasRole('owner-1', GUMBA_ROLE.ADMIN), true);
    assert.strictEqual(tree.hasRole('owner-1', GUMBA_ROLE.OWNER), true);
    
    // Reader only has reader role
    assert.strictEqual(tree.hasRole('reader-1', GUMBA_ROLE.READER), true);
    assert.strictEqual(tree.hasRole('reader-1', GUMBA_ROLE.MEMBER), false);
    assert.strictEqual(tree.hasRole('reader-1', GUMBA_ROLE.ADMIN), false);
    assert.strictEqual(tree.hasRole('reader-1', GUMBA_ROLE.OWNER), false);
  });
  
  it('builds Merkle root', () => {
    tree.addMember('member-a', GUMBA_ROLE.MEMBER);
    tree.addMember('member-b', GUMBA_ROLE.MEMBER);
    tree.addMember('member-c', GUMBA_ROLE.MEMBER);
    
    const root = tree.getRoot();
    
    assert.ok(root);
    assert.strictEqual(root.length, 64); // SHA3-256 hex
  });
  
  it('generates and verifies Merkle proofs', () => {
    tree.addMember('member-a', GUMBA_ROLE.MEMBER);
    tree.addMember('member-b', GUMBA_ROLE.MEMBER);
    tree.addMember('member-c', GUMBA_ROLE.MEMBER);
    tree.addMember('member-d', GUMBA_ROLE.MEMBER);
    
    const proof = tree.getProof('member-b');
    
    assert.ok(proof);
    assert.ok(proof.leaf);
    assert.ok(proof.root);
    assert.ok(proof.path);
    
    // Verify the proof
    const valid = GumbaMemberTree.verifyProof(proof);
    assert.strictEqual(valid, true);
  });
  
  it('returns null proof for non-members', () => {
    tree.addMember('member-a', GUMBA_ROLE.MEMBER);
    
    const proof = tree.getProof('non-member');
    
    assert.strictEqual(proof, null);
  });
  
  it('exports and imports correctly', () => {
    tree.addMember('member-a', GUMBA_ROLE.OWNER);
    tree.addMember('member-b', GUMBA_ROLE.MEMBER);
    
    const exported = tree.export();
    
    const newTree = new GumbaMemberTree();
    newTree.import(exported);
    
    assert.strictEqual(newTree.isMember('member-a'), true);
    assert.strictEqual(newTree.isMember('member-b'), true);
    assert.strictEqual(newTree.getRole('member-a'), GUMBA_ROLE.OWNER);
    assert.strictEqual(newTree.getRoot(), tree.getRoot());
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// GUMBA PROOF TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('GumbaProof', () => {
  let alice;
  
  beforeEach(() => {
    alice = createTestIdentity('alice');
  });
  
  describe('Challenge-Response', () => {
    it('creates valid challenges', () => {
      const challenge = GumbaProof.createChallenge('test-bundle', alice.dokoId);
      
      assert.strictEqual(challenge.type, GUMBA_PROOF_TYPE.CHALLENGE);
      assert.strictEqual(challenge.bundleId, 'test-bundle');
      assert.strictEqual(challenge.targetDokoId, alice.dokoId);
      assert.ok(challenge.nonce);
      assert.ok(challenge.timestamp);
      assert.ok(challenge.expiry > Date.now());
    });
    
    it('signs challenges with DOKO key', () => {
      const challenge = GumbaProof.createChallenge('test-bundle', alice.dokoId);
      const signed = GumbaProof.signChallenge(challenge, alice.secretKey);
      
      assert.ok(signed.signature);
      assert.ok(signed.signedAt);
    });
    
    it('verifies valid signed challenges', () => {
      const challenge = GumbaProof.createChallenge('test-bundle', alice.dokoId);
      const signed = GumbaProof.signChallenge(challenge, alice.secretKey);
      
      const result = GumbaProof.verifyChallenge(signed, alice.publicKey);
      
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.reason, 'OK');
    });
    
    it('rejects challenges signed with wrong key', () => {
      const bob = createTestIdentity('bob');
      
      const challenge = GumbaProof.createChallenge('test-bundle', alice.dokoId);
      const signed = GumbaProof.signChallenge(challenge, alice.secretKey);
      
      const result = GumbaProof.verifyChallenge(signed, bob.publicKey);
      
      assert.strictEqual(result.valid, false);
    });
    
    it('rejects expired challenges', async () => {
      const challenge = GumbaProof.createChallenge('test-bundle', alice.dokoId);
      challenge.expiry = Date.now() - 1000; // Already expired
      
      const signed = GumbaProof.signChallenge(challenge, alice.secretKey);
      const result = GumbaProof.verifyChallenge(signed, alice.publicKey);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, 'EXPIRED');
    });
  });
  
  describe('Attestation', () => {
    let bob;
    let memberTree;
    
    beforeEach(() => {
      bob = createTestIdentity('bob');
      memberTree = new GumbaMemberTree();
      memberTree.addMember(alice.dokoId, GUMBA_ROLE.ADMIN);
    });
    
    it('creates attestations', () => {
      const attestation = GumbaProof.createAttestation({
        bundleId: 'test-bundle',
        grantorDokoId: alice.dokoId,
        granteeDokoId: bob.dokoId,
        grantorSecretKey: alice.secretKey,
        grantedRole: GUMBA_ROLE.READER,
      });
      
      assert.strictEqual(attestation.type, GUMBA_PROOF_TYPE.ATTESTATION);
      assert.strictEqual(attestation.grantorDokoId, alice.dokoId);
      assert.strictEqual(attestation.granteeDokoId, bob.dokoId);
      assert.strictEqual(attestation.grantedRole, GUMBA_ROLE.READER);
      assert.ok(attestation.signature);
    });
    
    it('verifies valid attestations', () => {
      const attestation = GumbaProof.createAttestation({
        bundleId: 'test-bundle',
        grantorDokoId: alice.dokoId,
        granteeDokoId: bob.dokoId,
        grantorSecretKey: alice.secretKey,
      });
      
      const result = GumbaProof.verifyAttestation(attestation, alice.publicKey, memberTree);
      
      assert.strictEqual(result.valid, true);
    });
    
    it('rejects attestations from non-members', () => {
      const charlie = createTestIdentity('charlie');
      
      const attestation = GumbaProof.createAttestation({
        bundleId: 'test-bundle',
        grantorDokoId: charlie.dokoId, // Not a member
        granteeDokoId: bob.dokoId,
        grantorSecretKey: charlie.secretKey,
      });
      
      const result = GumbaProof.verifyAttestation(attestation, charlie.publicKey, memberTree);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, 'GRANTOR_NOT_AUTHORIZED');
    });
    
    it('rejects expired attestations', () => {
      const attestation = GumbaProof.createAttestation({
        bundleId: 'test-bundle',
        grantorDokoId: alice.dokoId,
        granteeDokoId: bob.dokoId,
        grantorSecretKey: alice.secretKey,
        expiry: Date.now() - 1000, // Already expired
      });
      
      const result = GumbaProof.verifyAttestation(attestation, alice.publicKey, memberTree);
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, 'EXPIRED');
    });
  });
  
  describe('Merkle Proof', () => {
    let memberTree;
    
    beforeEach(() => {
      memberTree = new GumbaMemberTree();
      memberTree.addMember(alice.dokoId, GUMBA_ROLE.MEMBER);
      memberTree.addMember('other-1', GUMBA_ROLE.MEMBER);
      memberTree.addMember('other-2', GUMBA_ROLE.MEMBER);
    });
    
    it('creates Merkle proofs', () => {
      const proof = GumbaProof.createMerkleProof(alice.dokoId, memberTree);
      
      assert.ok(proof);
      assert.strictEqual(proof.type, GUMBA_PROOF_TYPE.MERKLE);
      assert.strictEqual(proof.dokoId, alice.dokoId);
      assert.ok(proof.proof);
    });
    
    it('verifies valid Merkle proofs', () => {
      const merkleProof = GumbaProof.createMerkleProof(alice.dokoId, memberTree);
      const result = GumbaProof.verifyMerkleProof(merkleProof, memberTree.getRoot());
      
      assert.strictEqual(result.valid, true);
    });
    
    it('rejects proofs with wrong root', () => {
      const merkleProof = GumbaProof.createMerkleProof(alice.dokoId, memberTree);
      const result = GumbaProof.verifyMerkleProof(merkleProof, 'wrong-root');
      
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.reason, 'ROOT_MISMATCH');
    });
    
    it('returns null for non-members', () => {
      const proof = GumbaProof.createMerkleProof('non-member', memberTree);
      assert.strictEqual(proof, null);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// GUMBA GATE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('GumbaGate', () => {
  let gate;
  let memberTree;
  let alice;
  
  beforeEach(() => {
    alice = createTestIdentity('alice');
    memberTree = new GumbaMemberTree();
    memberTree.addMember(alice.dokoId, GUMBA_ROLE.MEMBER);
    gate = new GumbaGate(memberTree);
  });
  
  it('issues challenges', () => {
    const challenge = gate.issueChallenge('test-bundle', alice.dokoId);
    
    assert.ok(challenge);
    assert.ok(challenge.nonce);
    assert.strictEqual(gate.stats.challengesIssued, 1);
  });
  
  it('verifies challenge-response access', async () => {
    const challenge = gate.issueChallenge('test-bundle', alice.dokoId);
    const signed = GumbaProof.signChallenge(challenge, alice.secretKey);
    
    const result = await gate.verifyAccess(signed, async (dokoId) => {
      if (dokoId === alice.dokoId) return alice.publicKey;
      return null;
    });
    
    assert.strictEqual(result.granted, true);
    assert.strictEqual(result.reason, 'CHALLENGE_VERIFIED');
    assert.strictEqual(result.role, GUMBA_ROLE.MEMBER);
    assert.strictEqual(gate.stats.accessGranted, 1);
  });
  
  it('denies access for non-members', async () => {
    const bob = createTestIdentity('bob');
    
    const challenge = gate.issueChallenge('test-bundle', bob.dokoId);
    const signed = GumbaProof.signChallenge(challenge, bob.secretKey);
    
    const result = await gate.verifyAccess(signed, async () => bob.publicKey);
    
    assert.strictEqual(result.granted, false);
    assert.strictEqual(result.reason, 'NOT_A_MEMBER');
  });
  
  it('prevents challenge replay', async () => {
    const challenge = gate.issueChallenge('test-bundle', alice.dokoId);
    const signed = GumbaProof.signChallenge(challenge, alice.secretKey);
    
    // First use - success
    const result1 = await gate.verifyAccess(signed, async () => alice.publicKey);
    assert.strictEqual(result1.granted, true);
    
    // Second use - fail (replay)
    const result2 = await gate.verifyAccess(signed, async () => alice.publicKey);
    assert.strictEqual(result2.granted, false);
    assert.strictEqual(result2.reason, 'CHALLENGE_NOT_FOUND_OR_EXPIRED');
    assert.strictEqual(gate.stats.replaysBlocked, 1);
  });
  
  it('caches successful proofs', async () => {
    const challenge = gate.issueChallenge('test-bundle', alice.dokoId);
    const signed = GumbaProof.signChallenge(challenge, alice.secretKey);
    
    await gate.verifyAccess(signed, async () => alice.publicKey);
    
    // Create new challenge but with same DOKO - should use cache
    const challenge2 = gate.issueChallenge('test-bundle', alice.dokoId);
    const signed2 = GumbaProof.signChallenge(challenge2, alice.secretKey);
    
    const result = await gate.verifyAccess(signed2, async () => alice.publicKey);
    
    assert.strictEqual(result.granted, true);
    assert.strictEqual(result.reason, 'CACHED');
  });
  
  it('revokes cached access', async () => {
    const challenge = gate.issueChallenge('test-bundle', alice.dokoId);
    const signed = GumbaProof.signChallenge(challenge, alice.secretKey);
    
    await gate.verifyAccess(signed, async () => alice.publicKey);
    
    // Revoke
    gate.revokeAccess(alice.dokoId);
    
    // New attempt should require fresh proof
    const challenge2 = gate.issueChallenge('test-bundle', alice.dokoId);
    const signed2 = GumbaProof.signChallenge(challenge2, alice.secretKey);
    
    const result = await gate.verifyAccess(signed2, async () => alice.publicKey);
    
    // Should be verified freshy, not from cache
    assert.strictEqual(result.reason, 'CHALLENGE_VERIFIED');
  });
  
  it('tracks statistics', async () => {
    const challenge = gate.issueChallenge('test-bundle', alice.dokoId);
    const signed = GumbaProof.signChallenge(challenge, alice.secretKey);
    
    await gate.verifyAccess(signed, async () => alice.publicKey);
    
    const stats = gate.getStats();
    
    assert.strictEqual(stats.challengesIssued, 1);
    assert.strictEqual(stats.accessGranted, 1);
    assert.strictEqual(stats.memberCount, 1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// GUMBA BUNDLE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('GumbaBundle', () => {
  let bundle;
  let owner;
  let ownerSecret;
  
  beforeEach(() => {
    owner = createTestIdentity('owner');
    ownerSecret = randomBytes(32);
    
    bundle = new GumbaBundle('test-bundle', {
      name: 'Test Bundle',
      description: 'A test GUMBA bundle',
      ownerDokoId: owner.dokoId,
    });
    
    bundle.initialize(ownerSecret);
  });
  
  afterEach(() => {
    bundle.destroy();
  });
  
  it('initializes with owner as member', () => {
    assert.strictEqual(bundle.memberTree.isMember(owner.dokoId), true);
    assert.strictEqual(bundle.memberTree.getRole(owner.dokoId), GUMBA_ROLE.OWNER);
  });
  
  it('adds messages', () => {
    const result = bundle.addMessage({ text: 'Hello' }, owner.dokoId);
    
    assert.ok(result.messageId);
    assert.ok(result.timestamp);
    assert.strictEqual(bundle.metadata.messageCount, 1);
  });
  
  it('prevents unauthorized message posting', () => {
    const stranger = createTestIdentity('stranger');
    
    assert.throws(() => {
      bundle.addMessage({ text: 'Hello' }, stranger.dokoId);
    }, /SENDER_NOT_AUTHORIZED/);
  });
  
  it('retrieves messages for authorized users', () => {
    bundle.addMessage({ text: 'Hello 1' }, owner.dokoId);
    bundle.addMessage({ text: 'Hello 2' }, owner.dokoId);
    bundle.addMessage({ text: 'Hello 3' }, owner.dokoId);
    
    const accessResult = { granted: true, role: GUMBA_ROLE.OWNER };
    const result = bundle.getMessages(accessResult);
    
    assert.strictEqual(result.messages.length, 3);
    assert.strictEqual(result.messages[0].content.text, 'Hello 1');
    assert.strictEqual(result.messages[2].content.text, 'Hello 3');
  });
  
  it('denies message retrieval without access', () => {
    bundle.addMessage({ text: 'Secret' }, owner.dokoId);
    
    assert.throws(() => {
      bundle.getMessages({ granted: false });
    }, /ACCESS_DENIED/);
  });
  
  it('adds members with proper authorization', () => {
    const alice = createTestIdentity('alice');
    
    bundle.addMember(alice.dokoId, GUMBA_ROLE.MEMBER, owner.dokoId);
    
    assert.strictEqual(bundle.memberTree.isMember(alice.dokoId), true);
    assert.strictEqual(bundle.memberTree.getRole(alice.dokoId), GUMBA_ROLE.MEMBER);
  });
  
  it('prevents unauthorized member addition', () => {
    const alice = createTestIdentity('alice');
    const bob = createTestIdentity('bob');
    
    // Alice is just a member, not admin
    bundle.addMember(alice.dokoId, GUMBA_ROLE.MEMBER, owner.dokoId);
    
    assert.throws(() => {
      bundle.addMember(bob.dokoId, GUMBA_ROLE.MEMBER, alice.dokoId);
    }, /ADDER_NOT_AUTHORIZED/);
  });
  
  it('prevents granting higher role than own', () => {
    const alice = createTestIdentity('alice');
    const bob = createTestIdentity('bob');
    
    bundle.addMember(alice.dokoId, GUMBA_ROLE.ADMIN, owner.dokoId);
    
    assert.throws(() => {
      bundle.addMember(bob.dokoId, GUMBA_ROLE.OWNER, alice.dokoId);
    }, /CANNOT_GRANT_HIGHER_ROLE/);
  });
  
  it('removes members with proper authorization', () => {
    const alice = createTestIdentity('alice');
    
    bundle.addMember(alice.dokoId, GUMBA_ROLE.MEMBER, owner.dokoId);
    bundle.removeMember(alice.dokoId, owner.dokoId);
    
    assert.strictEqual(bundle.memberTree.isMember(alice.dokoId), false);
  });
  
  it('prevents removing owner', () => {
    assert.throws(() => {
      bundle.removeMember(owner.dokoId, owner.dokoId);
    }, /CANNOT_REMOVE_OWNER/);
  });
  
  it('exports and imports bundles', () => {
    bundle.addMessage({ text: 'Test' }, owner.dokoId);
    
    const alice = createTestIdentity('alice');
    bundle.addMember(alice.dokoId, GUMBA_ROLE.MEMBER, owner.dokoId);
    
    const exported = bundle.export();
    
    assert.ok(exported.bundleId);
    assert.ok(exported.messages);
    assert.ok(exported.members);
    
    // Import into new bundle
    const imported = GumbaBundle.import(exported, ownerSecret);
    
    assert.strictEqual(imported.bundleId, bundle.bundleId);
    assert.strictEqual(imported.memberTree.isMember(alice.dokoId), true);
    assert.strictEqual(imported.metadata.messageCount, 1);
    
    // Can decrypt messages
    const result = imported.getMessages({ granted: true, role: GUMBA_ROLE.OWNER });
    assert.strictEqual(result.messages[0].content.text, 'Test');
    
    imported.destroy();
  });
  
  it('provides bundle info', () => {
    const info = bundle.getInfo();
    
    assert.strictEqual(info.bundleId, 'test-bundle');
    assert.strictEqual(info.name, 'Test Bundle');
    assert.strictEqual(info.memberCount, 1);
  });
  
  it('emits events on message and member changes', () => {
    const events = [];
    
    bundle.on('message', (data) => events.push({ type: 'message', ...data }));
    bundle.on('member:added', (data) => events.push({ type: 'member:added', ...data }));
    bundle.on('member:removed', (data) => events.push({ type: 'member:removed', ...data }));
    
    const alice = createTestIdentity('alice');
    bundle.addMember(alice.dokoId, GUMBA_ROLE.MEMBER, owner.dokoId);
    bundle.addMessage({ text: 'Test' }, owner.dokoId);
    bundle.removeMember(alice.dokoId, owner.dokoId);
    
    assert.strictEqual(events.length, 3);
    assert.strictEqual(events[0].type, 'member:added');
    assert.strictEqual(events[1].type, 'message');
    assert.strictEqual(events[2].type, 'member:removed');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// GUMBA HUB TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('GumbaHub', () => {
  let hub;
  let identity;
  
  beforeEach(() => {
    identity = createTestIdentity('node');
    identity.identity = identity; // Self-reference for hub
    
    hub = new GumbaHub(identity, null, {});
  });
  
  it('creates bundles', () => {
    const info = hub.createBundle('my-bundle', { name: 'My Bundle' });
    
    assert.strictEqual(info.bundleId, 'my-bundle');
    assert.strictEqual(info.name, 'My Bundle');
    assert.strictEqual(hub.stats.bundlesCreated, 1);
  });
  
  it('prevents duplicate bundle IDs', () => {
    hub.createBundle('my-bundle');
    
    assert.throws(() => {
      hub.createBundle('my-bundle');
    }, /BUNDLE_EXISTS/);
  });
  
  it('lists bundles', () => {
    hub.createBundle('bundle-1', { name: 'Bundle 1' });
    hub.createBundle('bundle-2', { name: 'Bundle 2' });
    
    const bundles = hub.listBundles();
    
    assert.strictEqual(bundles.length, 2);
    assert.ok(bundles.find(b => b.bundleId === 'bundle-1'));
    assert.ok(bundles.find(b => b.bundleId === 'bundle-2'));
  });
  
  it('issues challenges', () => {
    hub.createBundle('my-bundle');
    
    const challenge = hub.issueChallenge('my-bundle', 'some-doko');
    
    assert.ok(challenge.nonce);
    assert.strictEqual(challenge.bundleId, 'my-bundle');
  });
  
  it('returns error for unknown bundle challenges', () => {
    const result = hub.issueChallenge('nonexistent', 'some-doko');
    
    assert.ok(result.error);
    assert.strictEqual(result.error, 'BUNDLE_NOT_FOUND');
  });
  
  it('handles access requests', async () => {
    hub.createBundle('my-bundle');
    
    const bundle = hub.getBundle('my-bundle');
    bundle.memberTree.addMember(identity.dokoId, GUMBA_ROLE.MEMBER);
    
    const challenge = hub.issueChallenge('my-bundle', identity.dokoId);
    const signed = GumbaProof.signChallenge(challenge, identity.secretKey);
    
    const result = await hub.handleAccessRequest('my-bundle', signed, 'visitor-node');
    
    assert.strictEqual(result.granted, true);
    assert.ok(result.sessionId);
    assert.strictEqual(hub.sessions.size, 1);
  });
  
  it('gets messages for active sessions', async () => {
    hub.createBundle('my-bundle');
    
    const bundle = hub.getBundle('my-bundle');
    bundle.memberTree.addMember(identity.dokoId, GUMBA_ROLE.MEMBER);
    bundle.addMessage({ text: 'Test' }, identity.dokoId);
    
    const challenge = hub.issueChallenge('my-bundle', identity.dokoId);
    const signed = GumbaProof.signChallenge(challenge, identity.secretKey);
    const accessResult = await hub.handleAccessRequest('my-bundle', signed, 'visitor');
    
    const messages = await hub.getMessages(accessResult.sessionId);
    
    assert.strictEqual(messages.messages.length, 1);
    assert.strictEqual(messages.messages[0].content.text, 'Test');
  });
  
  it('posts messages for active sessions', async () => {
    hub.createBundle('my-bundle');
    
    const bundle = hub.getBundle('my-bundle');
    bundle.memberTree.addMember(identity.dokoId, GUMBA_ROLE.MEMBER);
    
    const challenge = hub.issueChallenge('my-bundle', identity.dokoId);
    const signed = GumbaProof.signChallenge(challenge, identity.secretKey);
    const accessResult = await hub.handleAccessRequest('my-bundle', signed, 'visitor');
    
    const postResult = await hub.postMessage(accessResult.sessionId, { text: 'New message' });
    
    assert.strictEqual(postResult.success, true);
    assert.ok(postResult.messageId);
  });
  
  it('cleans up expired sessions', async () => {
    hub.createBundle('my-bundle');
    
    const bundle = hub.getBundle('my-bundle');
    bundle.memberTree.addMember(identity.dokoId, GUMBA_ROLE.MEMBER);
    
    const challenge = hub.issueChallenge('my-bundle', identity.dokoId);
    const signed = GumbaProof.signChallenge(challenge, identity.secretKey);
    await hub.handleAccessRequest('my-bundle', signed, 'visitor');
    
    // Manually expire the session
    const session = Array.from(hub.sessions.values())[0];
    session.expiresAt = Date.now() - 1000;
    
    const cleaned = hub.cleanupSessions();
    
    assert.strictEqual(cleaned, 1);
    assert.strictEqual(hub.sessions.size, 0);
  });
  
  it('deletes bundles', () => {
    hub.createBundle('my-bundle');
    
    const result = hub.deleteBundle('my-bundle', identity.dokoId);
    
    assert.strictEqual(result.success, true);
    assert.strictEqual(hub.bundles.size, 0);
  });
  
  it('tracks statistics', () => {
    hub.createBundle('bundle-1');
    hub.createBundle('bundle-2');
    
    const stats = hub.getStats();
    
    assert.strictEqual(stats.bundlesCreated, 2);
    assert.strictEqual(stats.activeBundles, 2);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('GUMBA Integration', () => {
  it('complete access flow: challenge → verify → read', async () => {
    // Setup
    const nodeOwner = createTestIdentity('node-owner');
    const visitor = createTestIdentity('visitor');
    
    nodeOwner.identity = nodeOwner;
    const hub = new GumbaHub(nodeOwner, null);
    
    // Register visitor's public key for verification
    hub.registerPublicKey(visitor.dokoId, visitor.publicKey);
    
    // Create bundle and add visitor as member
    hub.createBundle('chat-room', { name: 'Chat Room' });
    const bundle = hub.getBundle('chat-room');
    bundle.memberTree.addMember(visitor.dokoId, GUMBA_ROLE.MEMBER, nodeOwner.dokoId);
    
    // Add some messages
    bundle.addMessage({ text: 'Welcome!' }, nodeOwner.dokoId);
    bundle.addMessage({ text: 'How are you?' }, nodeOwner.dokoId);
    
    // Visitor requests access
    const challenge = hub.issueChallenge('chat-room', visitor.dokoId);
    
    // Visitor signs the challenge
    const proof = GumbaProof.signChallenge(challenge, visitor.secretKey);
    
    // Hub verifies and grants access
    const accessResult = await hub.handleAccessRequest('chat-room', proof, 'visitor-node');
    
    assert.strictEqual(accessResult.granted, true);
    
    // Visitor retrieves messages
    const messages = await hub.getMessages(accessResult.sessionId);
    
    assert.strictEqual(messages.messages.length, 2);
    assert.strictEqual(messages.messages[0].content.text, 'Welcome!');
    
    // Visitor posts a message
    const postResult = await hub.postMessage(accessResult.sessionId, { text: 'Hello back!' });
    
    assert.strictEqual(postResult.success, true);
    
    // Verify message is in bundle
    const allMessages = await hub.getMessages(accessResult.sessionId);
    assert.strictEqual(allMessages.messages.length, 3);
  });
  
  it('attestation-based access flow', async () => {
    const nodeOwner = createTestIdentity('node-owner');
    const alice = createTestIdentity('alice');
    const bob = createTestIdentity('bob');
    
    nodeOwner.identity = nodeOwner;
    const hub = new GumbaHub(nodeOwner, null);
    
    // Create bundle with alice as admin
    hub.createBundle('private-room');
    const bundle = hub.getBundle('private-room');
    bundle.memberTree.addMember(alice.dokoId, GUMBA_ROLE.ADMIN, nodeOwner.dokoId);
    
    // Alice creates attestation for Bob
    const attestation = GumbaProof.createAttestation({
      bundleId: 'private-room',
      grantorDokoId: alice.dokoId,
      granteeDokoId: bob.dokoId,
      grantorSecretKey: alice.secretKey,
      grantedRole: GUMBA_ROLE.READER,
    });
    
    // Bob uses attestation to access
    // Note: Hub needs to be able to get Alice's public key
    const mockGetPublicKey = async (dokoId) => {
      if (dokoId === alice.dokoId) return alice.publicKey;
      if (dokoId === bob.dokoId) return bob.publicKey;
      return null;
    };
    
    // Directly test the gate
    const accessResult = await bundle.gate.verifyAccess(attestation, mockGetPublicKey);
    
    assert.strictEqual(accessResult.granted, true);
    assert.strictEqual(accessResult.reason, 'ATTESTATION_VERIFIED');
    assert.strictEqual(accessResult.role, GUMBA_ROLE.READER);
  });
  
  it('access revocation flow', async () => {
    const nodeOwner = createTestIdentity('node-owner');
    const alice = createTestIdentity('alice');
    
    nodeOwner.identity = nodeOwner;
    const hub = new GumbaHub(nodeOwner, null);
    
    // Register alice's public key for verification
    hub.registerPublicKey(alice.dokoId, alice.publicKey);
    
    hub.createBundle('private-room');
    const bundle = hub.getBundle('private-room');
    bundle.memberTree.addMember(alice.dokoId, GUMBA_ROLE.MEMBER, nodeOwner.dokoId);
    
    // Alice gets access
    const challenge = hub.issueChallenge('private-room', alice.dokoId);
    const proof = GumbaProof.signChallenge(challenge, alice.secretKey);
    const access = await hub.handleAccessRequest('private-room', proof, 'alice-node');
    
    assert.strictEqual(access.granted, true);
    
    // Owner removes Alice
    bundle.removeMember(alice.dokoId, nodeOwner.dokoId);
    
    // Alice's session should still work (cached)
    const messages1 = await hub.getMessages(access.sessionId);
    assert.ok(messages1.messages);
    
    // But new access attempts should fail
    const challenge2 = hub.issueChallenge('private-room', alice.dokoId);
    const proof2 = GumbaProof.signChallenge(challenge2, alice.secretKey);
    const access2 = await hub.handleAccessRequest('private-room', proof2, 'alice-node');
    
    assert.strictEqual(access2.granted, false);
    assert.strictEqual(access2.reason, 'NOT_A_MEMBER');
  });
});

console.log('GUMBA tests loaded');
