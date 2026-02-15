/**
 * GUMBA - Guarded Universal Message Bundle Access
 * 
 * A novel cryptographic access control system where:
 * - Keys NEVER leave the host node
 * - Access is granted via cryptographic PROOFS, not key distribution
 * - The proof IS the access - not the key
 * 
 * ╔═══════════════════════════════════════════════════════════════════════════════╗
 * ║  "The key is not the access. The proof is the access."                        ║
 * ║                                                                               ║
 * ║  Like a guarded temple: You don't get a copy of the master key.              ║
 * ║  You prove you belong. The guardian opens the door.                          ║
 * ║  The door stays locked. The key stays hidden.                                 ║
 * ╚═══════════════════════════════════════════════════════════════════════════════╝
 * 
 * SECURITY MODEL:
 * - Bundle Key: Derived deterministically, never transmitted
 * - Membership: Merkle tree of authorized DOKO hashes
 * - Access Proof: Challenge-response, attestation, or ZK proof
 * - Content Delivery: Via ANNEX E2E tunnel after access granted
 * 
 * PROOF TYPES:
 * 1. CHALLENGE - Sign a nonce with DOKO private key
 * 2. ATTESTATION - Another member vouches for you (time-limited)
 * 3. MERKLE - Prove membership in tree without revealing identity
 * 
 * Part of the Himalayan Protocol Family:
 * - ANNEX: E2E encrypted channels (used for content delivery)
 * - DOKO: Identity certificates (used for membership)
 * - GUMBA: Access control (this module)
 * 
 * Named after the Tibetan word for "monastery" - a guarded sacred space
 * where access is granted to those who prove their dedication.
 * 
 * @module mesh/gumba
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { randomBytes, createCipheriv, createDecipheriv, createHash } from 'crypto';
import { sha3_256 as _nobleSha3 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
// ACCEL: Hardware-accelerated crypto
import { sha3_256, mlDsa65Sign, mlDsa65Verify } from '../utils/accel.js';
import { createLogger } from '../utils/logger.js';
import EventEmitter from 'events';

const log = createLogger('mesh:gumba');

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

export const GUMBA_CONFIG = Object.freeze({
  // Encryption
  symmetricAlgorithm: 'aes-256-gcm',
  nonceSize: 12,
  authTagLength: 16,
  
  // Key derivation
  keyDerivationSalt: 'YAKMESH-GUMBA-2026',
  bundleVersion: 1,
  
  // Access control
  challengeExpiry: 30000,         // 30 second challenge window
  attestationMaxAge: 86400000,    // 24 hour attestation validity
  proofCacheTime: 300000,         // 5 minute proof cache
  
  // Bundle limits
  maxBundleSize: 10 * 1024 * 1024, // 10MB max bundle
  maxMembers: 10000,               // Max members per bundle
  maxMessagesPerBundle: 100000,    // Max messages before rotation
  
  // Message types
  messageTypes: {
    // Access protocol
    CHALLENGE: 'gumba:challenge',
    RESPONSE: 'gumba:response',
    ACCESS_GRANTED: 'gumba:access_granted',
    ACCESS_DENIED: 'gumba:access_denied',
    
    // Attestation
    ATTEST: 'gumba:attest',
    REVOKE_ATTEST: 'gumba:revoke_attest',
    
    // Content
    CONTENT: 'gumba:content',
    SYNC: 'gumba:sync',
    
    // Membership
    MEMBER_ADD: 'gumba:member_add',
    MEMBER_REMOVE: 'gumba:member_remove',
  },
});

/**
 * Proof types for access verification
 */
export const GUMBA_PROOF_TYPE = Object.freeze({
  CHALLENGE: 'challenge',      // Direct challenge-response
  ATTESTATION: 'attestation',  // Vouched by existing member
  MERKLE: 'merkle',           // ZK merkle inclusion proof
});

/**
 * Member roles in a GUMBA bundle
 */
export const GUMBA_ROLE = Object.freeze({
  OWNER: 'owner',       // Can add/remove members, delete bundle
  ADMIN: 'admin',       // Can add/remove members
  MEMBER: 'member',     // Can read and write
  READER: 'reader',     // Can only read
});

// ═══════════════════════════════════════════════════════════════════════════════
// GUMBA KEY - Deterministic key derivation (NEVER transmitted)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * GumbaKey - The bundle encryption key
 * 
 * Derived deterministically from owner's secret + bundle ID.
 * This key NEVER leaves the host node. Ever.
 */
export class GumbaKey {
  /**
   * @param {string} bundleId - Unique bundle identifier
   * @param {Uint8Array} ownerSecret - Owner's secret key material
   */
  constructor(bundleId, ownerSecret) {
    this.bundleId = bundleId;
    this.createdAt = Date.now();
    
    // Derive the bundle key (deterministic, reproducible on same node)
    this.key = this._deriveKey(ownerSecret);
    
    // Track usage for rotation
    this.messageCount = 0;
    this.lastUsed = Date.now();
  }
  
  /**
   * Derive encryption key from owner secret
   * Uses HKDF-like construction with SHA3-256
   */
  _deriveKey(ownerSecret) {
    // Stage 1: Extract
    const prk = createHash('sha3-256')
      .update(GUMBA_CONFIG.keyDerivationSalt)
      .update(ownerSecret)
      .digest();
    
    // Stage 2: Expand with bundle context
    const info = Buffer.concat([
      utf8ToBytes(`GUMBA-v${GUMBA_CONFIG.bundleVersion}`),
      utf8ToBytes(':'),
      utf8ToBytes(this.bundleId),
    ]);
    
    return createHash('sha3-256')
      .update(prk)
      .update(info)
      .update(Buffer.from([0x01])) // Counter for HKDF
      .digest();
  }
  
  /**
   * Encrypt content into the bundle
   */
  seal(plaintext, metadata = {}) {
    const nonce = randomBytes(GUMBA_CONFIG.nonceSize);
    const cipher = createCipheriv(
      GUMBA_CONFIG.symmetricAlgorithm,
      this.key,
      nonce,
      { authTagLength: GUMBA_CONFIG.authTagLength }
    );
    
    // Include metadata in AAD for integrity
    const aad = Buffer.from(JSON.stringify({
      bundleId: this.bundleId,
      timestamp: Date.now(),
      ...metadata,
    }));
    cipher.setAAD(aad);
    
    const data = typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext);
    const encrypted = Buffer.concat([
      cipher.update(data, 'utf8'),
      cipher.final(),
    ]);
    
    this.messageCount++;
    this.lastUsed = Date.now();
    
    return {
      nonce: nonce.toString('hex'),
      ciphertext: encrypted.toString('hex'),
      authTag: cipher.getAuthTag().toString('hex'),
      aad: aad.toString('hex'),
    };
  }
  
  /**
   * Decrypt content from the bundle
   * Only called locally - plaintext delivered via ANNEX
   */
  unseal(encrypted) {
    const nonce = Buffer.from(encrypted.nonce, 'hex');
    const ciphertext = Buffer.from(encrypted.ciphertext, 'hex');
    const authTag = Buffer.from(encrypted.authTag, 'hex');
    const aad = Buffer.from(encrypted.aad, 'hex');
    
    const decipher = createDecipheriv(
      GUMBA_CONFIG.symmetricAlgorithm,
      this.key,
      nonce,
      { authTagLength: GUMBA_CONFIG.authTagLength }
    );
    
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    
    return decrypted.toString('utf8');
  }
  
  /**
   * Check if key needs rotation
   */
  needsRotation() {
    return this.messageCount >= GUMBA_CONFIG.maxMessagesPerBundle;
  }
  
  /**
   * Securely clear key material
   */
  destroy() {
    if (this.key) {
      this.key.fill(0);
      this.key = null;
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GUMBA MEMBER TREE - Merkle tree for membership proofs
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * MemberTree - Merkle tree of authorized DOKO identities
 * 
 * Enables:
 * - O(log n) membership verification
 * - Merkle proofs for ZK-style access
 * - Efficient member add/remove
 */
export class GumbaMemberTree {
  constructor() {
    this.members = new Map(); // dokoId -> { role, addedAt, addedBy }
    this.leafHashes = [];     // Sorted leaf hashes
    this.root = null;         // Merkle root
    this.dirty = true;        // Needs rebuild
  }
  
  /**
   * Hash a DOKO ID for tree inclusion
   */
  static hashMember(dokoId, role) {
    return bytesToHex(sha3_256(utf8ToBytes(`${dokoId}:${role}`)));
  }
  
  /**
   * Add a member to the tree
   */
  addMember(dokoId, role = GUMBA_ROLE.MEMBER, addedBy = null) {
    if (this.members.size >= GUMBA_CONFIG.maxMembers) {
      throw new Error('Maximum members reached');
    }
    
    this.members.set(dokoId, {
      role,
      addedAt: Date.now(),
      addedBy,
    });
    
    this.dirty = true;
    log.debug('Member added', { dokoId: dokoId.slice(0, 16), role });
    
    return true;
  }
  
  /**
   * Remove a member from the tree
   */
  removeMember(dokoId) {
    const removed = this.members.delete(dokoId);
    if (removed) {
      this.dirty = true;
      log.debug('Member removed', { dokoId: dokoId.slice(0, 16) });
    }
    return removed;
  }
  
  /**
   * Check if a DOKO is a member
   */
  isMember(dokoId) {
    return this.members.has(dokoId);
  }
  
  /**
   * Get member info
   */
  getMember(dokoId) {
    return this.members.get(dokoId) || null;
  }
  
  /**
   * Get member role
   */
  getRole(dokoId) {
    return this.members.get(dokoId)?.role || null;
  }
  
  /**
   * Check if member has required role
   */
  hasRole(dokoId, requiredRole) {
    const member = this.members.get(dokoId);
    if (!member) return false;
    
    const roleHierarchy = [GUMBA_ROLE.READER, GUMBA_ROLE.MEMBER, GUMBA_ROLE.ADMIN, GUMBA_ROLE.OWNER];
    const memberLevel = roleHierarchy.indexOf(member.role);
    const requiredLevel = roleHierarchy.indexOf(requiredRole);
    
    return memberLevel >= requiredLevel;
  }
  
  /**
   * Rebuild the Merkle tree
   */
  rebuild() {
    if (!this.dirty) return this.root;
    
    // Create sorted leaf hashes
    this.leafHashes = Array.from(this.members.entries())
      .map(([dokoId, info]) => GumbaMemberTree.hashMember(dokoId, info.role))
      .sort();
    
    if (this.leafHashes.length === 0) {
      this.root = bytesToHex(sha3_256(utf8ToBytes('GUMBA:EMPTY')));
    } else {
      this.root = this._buildTree(this.leafHashes);
    }
    
    this.dirty = false;
    return this.root;
  }
  
  /**
   * Build Merkle tree recursively
   */
  _buildTree(leaves) {
    if (leaves.length === 1) return leaves[0];
    
    const nextLevel = [];
    for (let i = 0; i < leaves.length; i += 2) {
      const left = leaves[i];
      const right = leaves[i + 1] || left; // Duplicate if odd
      const parent = bytesToHex(sha3_256(hexToBytes(left + right)));
      nextLevel.push(parent);
    }
    
    return this._buildTree(nextLevel);
  }
  
  /**
   * Generate Merkle proof for a member
   */
  getProof(dokoId) {
    const member = this.members.get(dokoId);
    if (!member) return null;
    
    this.rebuild();
    
    const leafHash = GumbaMemberTree.hashMember(dokoId, member.role);
    const leafIndex = this.leafHashes.indexOf(leafHash);
    if (leafIndex === -1) return null;
    
    const proof = [];
    let currentLevel = [...this.leafHashes];
    let index = leafIndex;
    
    while (currentLevel.length > 1) {
      const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
      const sibling = currentLevel[siblingIndex] || currentLevel[index];
      
      proof.push({
        hash: sibling,
        position: index % 2 === 0 ? 'right' : 'left',
      });
      
      // Move to next level
      const nextLevel = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = currentLevel[i + 1] || left;
        nextLevel.push(bytesToHex(sha3_256(hexToBytes(left + right))));
      }
      
      currentLevel = nextLevel;
      index = Math.floor(index / 2);
    }
    
    return {
      leaf: leafHash,
      root: this.root,
      path: proof,
    };
  }
  
  /**
   * Verify a Merkle proof
   */
  static verifyProof(proof) {
    let current = proof.leaf;
    
    for (const step of proof.path) {
      const combined = step.position === 'left' 
        ? step.hash + current 
        : current + step.hash;
      current = bytesToHex(sha3_256(hexToBytes(combined)));
    }
    
    return current === proof.root;
  }
  
  /**
   * Get the current root
   */
  getRoot() {
    return this.rebuild();
  }
  
  /**
   * Get member count
   */
  get size() {
    return this.members.size;
  }
  
  /**
   * Export member list (for backup/sync)
   */
  export() {
    return {
      root: this.getRoot(),
      members: Array.from(this.members.entries()).map(([dokoId, info]) => ({
        dokoId,
        ...info,
      })),
    };
  }
  
  /**
   * Import member list
   */
  import(data) {
    this.members.clear();
    for (const member of data.members) {
      this.members.set(member.dokoId, {
        role: member.role,
        addedAt: member.addedAt,
        addedBy: member.addedBy,
      });
    }
    this.dirty = true;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GUMBA PROOF - Access proof generation and verification
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * GumbaProof - Creates and verifies access proofs
 */
export class GumbaProof {
  /**
   * Create a challenge for proof-of-identity
   */
  static createChallenge(bundleId, targetDokoId) {
    const nonce = bytesToHex(randomBytes(32));
    const timestamp = Date.now();
    
    return {
      type: GUMBA_PROOF_TYPE.CHALLENGE,
      bundleId,
      targetDokoId,
      nonce,
      timestamp,
      expiry: timestamp + GUMBA_CONFIG.challengeExpiry,
    };
  }
  
  /**
   * Sign a challenge response with DOKO private key
   */
  static signChallenge(challenge, secretKey) {
    const payload = JSON.stringify({
      type: challenge.type,
      bundleId: challenge.bundleId,
      nonce: challenge.nonce,
      timestamp: challenge.timestamp,
    });
    
    const payloadBytes = utf8ToBytes(payload);
    // API: sign(message, secretKey)
    const signature = mlDsa65Sign(payloadBytes, secretKey);
    
    return {
      ...challenge,
      signature: bytesToHex(signature),
      signedAt: Date.now(),
    };
  }
  
  /**
   * Verify a challenge response
   */
  static verifyChallenge(response, publicKey) {
    // Check expiry
    if (Date.now() > response.expiry) {
      return { valid: false, reason: 'EXPIRED' };
    }
    
    // Rebuild payload
    const payload = JSON.stringify({
      type: response.type,
      bundleId: response.bundleId,
      nonce: response.nonce,
      timestamp: response.timestamp,
    });
    
    // Verify signature
    try {
      const payloadBytes = utf8ToBytes(payload);
      const signatureBytes = hexToBytes(response.signature);
      const publicKeyBytes = typeof publicKey === 'string' 
        ? hexToBytes(publicKey) 
        : publicKey;
      
      // API: verify(signature, message, publicKey)
      const valid = mlDsa65Verify(signatureBytes, payloadBytes, publicKeyBytes);
      
      return { valid, reason: valid ? 'OK' : 'INVALID_SIGNATURE' };
    } catch (err) {
      return { valid: false, reason: 'VERIFICATION_ERROR', error: err.message };
    }
  }
  
  /**
   * Create an attestation (one member vouches for another)
   */
  static createAttestation(options) {
    const {
      bundleId,
      grantorDokoId,
      granteeDokoId,
      grantorSecretKey,
      expiry = Date.now() + GUMBA_CONFIG.attestationMaxAge,
      grantedRole = GUMBA_ROLE.READER,
    } = options;
    
    const attestation = {
      type: GUMBA_PROOF_TYPE.ATTESTATION,
      bundleId,
      grantorDokoId,
      granteeDokoId,
      grantedRole,
      createdAt: Date.now(),
      expiry,
    };
    
    // Sign with grantor's key
    const payload = JSON.stringify(attestation);
    const payloadBytes = utf8ToBytes(payload);
    // API: sign(message, secretKey)
    const signature = mlDsa65Sign(payloadBytes, grantorSecretKey);
    
    return {
      ...attestation,
      signature: bytesToHex(signature),
    };
  }
  
  /**
   * Verify an attestation
   */
  static verifyAttestation(attestation, grantorPublicKey, memberTree) {
    // Check expiry
    if (Date.now() > attestation.expiry) {
      return { valid: false, reason: 'EXPIRED' };
    }
    
    // Check grantor is a member with sufficient role
    if (!memberTree.hasRole(attestation.grantorDokoId, GUMBA_ROLE.MEMBER)) {
      return { valid: false, reason: 'GRANTOR_NOT_AUTHORIZED' };
    }
    
    // Verify signature
    try {
      const payload = JSON.stringify({
        type: attestation.type,
        bundleId: attestation.bundleId,
        grantorDokoId: attestation.grantorDokoId,
        granteeDokoId: attestation.granteeDokoId,
        grantedRole: attestation.grantedRole,
        createdAt: attestation.createdAt,
        expiry: attestation.expiry,
      });
      
      const payloadBytes = utf8ToBytes(payload);
      const signatureBytes = hexToBytes(attestation.signature);
      const publicKeyBytes = typeof grantorPublicKey === 'string'
        ? hexToBytes(grantorPublicKey)
        : grantorPublicKey;
      
      // API: verify(signature, message, publicKey)
      const valid = mlDsa65Verify(signatureBytes, payloadBytes, publicKeyBytes);
      
      return { valid, reason: valid ? 'OK' : 'INVALID_SIGNATURE' };
    } catch (err) {
      return { valid: false, reason: 'VERIFICATION_ERROR', error: err.message };
    }
  }
  
  /**
   * Create a Merkle membership proof
   */
  static createMerkleProof(dokoId, memberTree) {
    const proof = memberTree.getProof(dokoId);
    if (!proof) {
      return null;
    }
    
    return {
      type: GUMBA_PROOF_TYPE.MERKLE,
      dokoId, // Could be hidden for true ZK
      proof,
      timestamp: Date.now(),
    };
  }
  
  /**
   * Verify a Merkle membership proof
   */
  static verifyMerkleProof(merkleProof, expectedRoot) {
    if (!merkleProof || !merkleProof.proof) {
      return { valid: false, reason: 'INVALID_PROOF' };
    }
    
    // Check root matches current tree
    if (merkleProof.proof.root !== expectedRoot) {
      return { valid: false, reason: 'ROOT_MISMATCH' };
    }
    
    // Verify the proof path
    const valid = GumbaMemberTree.verifyProof(merkleProof.proof);
    
    return { valid, reason: valid ? 'OK' : 'PROOF_INVALID' };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GUMBA GATE - Access control and content gating
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * GumbaGate - The guardian at the door
 * 
 * Verifies proofs and grants/denies access to bundles.
 * "Show your proof. The guardian will decide."
 */
export class GumbaGate {
  constructor(memberTree, options = {}) {
    this.memberTree = memberTree;
    this.options = options;
    
    // Pending challenges awaiting response
    this.pendingChallenges = new Map(); // nonce -> challenge
    
    // Proof cache (prevent replay, speed up repeated access)
    this.proofCache = new Map(); // dokoId -> { proof, expiresAt }
    
    // Stats
    this.stats = {
      challengesIssued: 0,
      accessGranted: 0,
      accessDenied: 0,
      replaysBlocked: 0,
    };
  }
  
  /**
   * Issue a challenge to an access requester
   */
  issueChallenge(bundleId, requesterDokoId) {
    const challenge = GumbaProof.createChallenge(bundleId, requesterDokoId);
    
    // Store pending challenge
    this.pendingChallenges.set(challenge.nonce, challenge);
    
    // Set expiry cleanup
    setTimeout(() => {
      this.pendingChallenges.delete(challenge.nonce);
    }, GUMBA_CONFIG.challengeExpiry);
    
    this.stats.challengesIssued++;
    log.debug('Challenge issued', { 
      bundleId, 
      requester: requesterDokoId.slice(0, 16),
      nonce: challenge.nonce.slice(0, 16),
    });
    
    return challenge;
  }
  
  /**
   * Verify an access attempt
   * Returns access decision
   */
  async verifyAccess(proof, getPublicKey) {
    // For challenge-response, check if nonce is valid BEFORE cache
    // This prevents replay attacks where same signed response is used twice
    if (proof.type === GUMBA_PROOF_TYPE.CHALLENGE) {
      const pending = this.pendingChallenges.get(proof.nonce);
      if (!pending) {
        this.stats.replaysBlocked++;
        this.stats.accessDenied++;
        return { granted: false, reason: 'CHALLENGE_NOT_FOUND_OR_EXPIRED' };
      }
    }
    
    // Check proof cache (for non-challenge types, or after nonce validation)
    const cached = this._checkCache(proof);
    if (cached) {
      // For challenges, still consume the nonce even if cache hit
      if (proof.type === GUMBA_PROOF_TYPE.CHALLENGE) {
        this.pendingChallenges.delete(proof.nonce);
      }
      log.debug('Access granted from cache', { dokoId: cached.dokoId?.slice(0, 16) });
      this.stats.accessGranted++;
      return { granted: true, reason: 'CACHED', role: cached.role };
    }
    
    let result;
    
    switch (proof.type) {
      case GUMBA_PROOF_TYPE.CHALLENGE:
        result = await this._verifyChallengeAccess(proof, getPublicKey);
        break;
        
      case GUMBA_PROOF_TYPE.ATTESTATION:
        result = await this._verifyAttestationAccess(proof, getPublicKey);
        break;
        
      case GUMBA_PROOF_TYPE.MERKLE:
        result = this._verifyMerkleAccess(proof);
        break;
        
      default:
        result = { granted: false, reason: 'UNKNOWN_PROOF_TYPE' };
    }
    
    // Update stats and cache
    if (result.granted) {
      this.stats.accessGranted++;
      this._cacheProof(proof, result);
    } else {
      this.stats.accessDenied++;
    }
    
    log.debug('Access decision', { 
      type: proof.type, 
      granted: result.granted, 
      reason: result.reason,
    });
    
    return result;
  }
  
  /**
   * Verify challenge-response access
   */
  async _verifyChallengeAccess(response, getPublicKey) {
    // Check if this challenge is pending
    const pending = this.pendingChallenges.get(response.nonce);
    if (!pending) {
      this.stats.replaysBlocked++;
      return { granted: false, reason: 'CHALLENGE_NOT_FOUND_OR_EXPIRED' };
    }
    
    // Remove from pending (one-time use)
    this.pendingChallenges.delete(response.nonce);
    
    // Check membership
    const dokoId = response.targetDokoId;
    if (!this.memberTree.isMember(dokoId)) {
      return { granted: false, reason: 'NOT_A_MEMBER' };
    }
    
    // Get public key
    const publicKey = await getPublicKey(dokoId);
    if (!publicKey) {
      return { granted: false, reason: 'PUBLIC_KEY_NOT_FOUND' };
    }
    
    // Verify signature
    const verification = GumbaProof.verifyChallenge(response, publicKey);
    if (!verification.valid) {
      return { granted: false, reason: verification.reason };
    }
    
    const role = this.memberTree.getRole(dokoId);
    return { granted: true, reason: 'CHALLENGE_VERIFIED', role, dokoId };
  }
  
  /**
   * Verify attestation-based access
   */
  async _verifyAttestationAccess(attestation, getPublicKey) {
    // Get grantor's public key
    const grantorPublicKey = await getPublicKey(attestation.grantorDokoId);
    if (!grantorPublicKey) {
      return { granted: false, reason: 'GRANTOR_KEY_NOT_FOUND' };
    }
    
    // Verify attestation
    const verification = GumbaProof.verifyAttestation(
      attestation, 
      grantorPublicKey, 
      this.memberTree
    );
    
    if (!verification.valid) {
      return { granted: false, reason: verification.reason };
    }
    
    // Attestation is valid - grantee gets the granted role
    return { 
      granted: true, 
      reason: 'ATTESTATION_VERIFIED', 
      role: attestation.grantedRole,
      dokoId: attestation.granteeDokoId,
      attestedBy: attestation.grantorDokoId,
    };
  }
  
  /**
   * Verify Merkle proof access
   */
  _verifyMerkleAccess(merkleProof) {
    const expectedRoot = this.memberTree.getRoot();
    const verification = GumbaProof.verifyMerkleProof(merkleProof, expectedRoot);
    
    if (!verification.valid) {
      return { granted: false, reason: verification.reason };
    }
    
    const role = this.memberTree.getRole(merkleProof.dokoId);
    return { 
      granted: true, 
      reason: 'MERKLE_VERIFIED', 
      role,
      dokoId: merkleProof.dokoId,
    };
  }
  
  /**
   * Check proof cache
   */
  _checkCache(proof) {
    const dokoId = proof.targetDokoId || proof.granteeDokoId || proof.dokoId;
    if (!dokoId) return null;
    
    const cached = this.proofCache.get(dokoId);
    if (cached && cached.expiresAt > Date.now()) {
      return cached;
    }
    
    // Expired - remove
    if (cached) {
      this.proofCache.delete(dokoId);
    }
    
    return null;
  }
  
  /**
   * Cache a successful proof
   */
  _cacheProof(proof, result) {
    const dokoId = result.dokoId;
    if (!dokoId) return;
    
    this.proofCache.set(dokoId, {
      dokoId,
      role: result.role,
      expiresAt: Date.now() + GUMBA_CONFIG.proofCacheTime,
    });
  }
  
  /**
   * Clear proof cache for a DOKO (e.g., on revocation)
   */
  revokeAccess(dokoId) {
    this.proofCache.delete(dokoId);
    log.debug('Access revoked', { dokoId: dokoId.slice(0, 16) });
  }
  
  /**
   * Get gate statistics
   */
  getStats() {
    return {
      ...this.stats,
      pendingChallenges: this.pendingChallenges.size,
      cachedProofs: this.proofCache.size,
      memberCount: this.memberTree.size,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GUMBA BUNDLE - The encrypted content container
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * GumbaBundle - Encrypted message storage
 * 
 * "Like a treasure chest in the monastery vault.
 *  The key stays with the guardian. Visitors see only what they're shown."
 */
export class GumbaBundle extends EventEmitter {
  /**
   * @param {string} bundleId - Unique bundle identifier
   * @param {Object} options - Bundle configuration
   */
  constructor(bundleId, options = {}) {
    super();
    
    this.bundleId = bundleId;
    this.name = options.name || bundleId;
    this.description = options.description || '';
    this.createdAt = Date.now();
    this.ownerDokoId = options.ownerDokoId;
    
    // The key - NEVER LEAVES THIS NODE
    this.key = null;
    
    // Membership
    this.memberTree = new GumbaMemberTree();
    
    // Access control
    this.gate = new GumbaGate(this.memberTree);
    
    // Encrypted content storage
    this.messages = [];      // Sealed messages
    this.messageIndex = 0;   // Next message ID
    
    // Metadata (not encrypted)
    this.metadata = {
      version: GUMBA_CONFIG.bundleVersion,
      createdAt: this.createdAt,
      messageCount: 0,
      lastActivity: this.createdAt,
    };
  }
  
  /**
   * Initialize the bundle with owner's secret
   * This derives the bundle key (never transmitted)
   */
  initialize(ownerSecret) {
    this.key = new GumbaKey(this.bundleId, ownerSecret);
    
    // Add owner as first member
    if (this.ownerDokoId) {
      this.memberTree.addMember(this.ownerDokoId, GUMBA_ROLE.OWNER);
    }
    
    log.info('Bundle initialized', { 
      bundleId: this.bundleId, 
      owner: this.ownerDokoId?.slice(0, 16),
    });
    
    return this;
  }
  
  /**
   * Add a message to the bundle
   * @param {Object} content - Message content
   * @param {string} senderDokoId - Sender's DOKO ID
   * @returns {Object} Sealed message reference
   */
  addMessage(content, senderDokoId) {
    if (!this.key) {
      throw new Error('Bundle not initialized');
    }
    
    // Verify sender is a member with write access
    if (!this.memberTree.hasRole(senderDokoId, GUMBA_ROLE.MEMBER)) {
      throw new Error('SENDER_NOT_AUTHORIZED');
    }
    
    const messageId = ++this.messageIndex;
    const timestamp = Date.now();
    
    // Create message envelope
    const envelope = {
      id: messageId,
      type: 'message',
      sender: senderDokoId,
      content,
      timestamp,
    };
    
    // Seal it
    const sealed = this.key.seal(envelope);
    
    // Store
    this.messages.push({
      id: messageId,
      sealed,
      timestamp,
      senderHint: senderDokoId.slice(0, 8), // Minimal hint for UI
    });
    
    // Update metadata
    this.metadata.messageCount++;
    this.metadata.lastActivity = timestamp;
    
    this.emit('message', { messageId, sender: senderDokoId, timestamp });
    
    return { messageId, timestamp };
  }
  
  /**
   * Get messages for an authorized accessor
   * Returns decrypted content (delivered via ANNEX)
   * 
   * @param {Object} accessResult - Result from gate.verifyAccess()
   * @param {Object} options - Query options
   */
  getMessages(accessResult, options = {}) {
    if (!accessResult.granted) {
      throw new Error('ACCESS_DENIED');
    }
    
    const { since = 0, limit = 50 } = options;
    
    // Filter by time/ID
    let messages = this.messages.filter(m => m.id > since);
    
    // Apply limit
    if (limit > 0) {
      messages = messages.slice(-limit);
    }
    
    // Decrypt for accessor
    const decrypted = messages.map(m => {
      try {
        const plaintext = this.key.unseal(m.sealed);
        return JSON.parse(plaintext);
      } catch (err) {
        log.error('Decrypt error', { messageId: m.id, error: err.message });
        return { id: m.id, error: 'DECRYPT_FAILED' };
      }
    });
    
    return {
      messages: decrypted,
      bundleId: this.bundleId,
      accessedAs: accessResult.role,
      count: decrypted.length,
    };
  }
  
  /**
   * Add a member to the bundle
   */
  addMember(dokoId, role, adderDokoId) {
    // Verify adder has permission
    if (!this.memberTree.hasRole(adderDokoId, GUMBA_ROLE.ADMIN)) {
      throw new Error('ADDER_NOT_AUTHORIZED');
    }
    
    // Can't grant higher role than your own
    const adderRole = this.memberTree.getRole(adderDokoId);
    const roleHierarchy = [GUMBA_ROLE.READER, GUMBA_ROLE.MEMBER, GUMBA_ROLE.ADMIN, GUMBA_ROLE.OWNER];
    if (roleHierarchy.indexOf(role) > roleHierarchy.indexOf(adderRole)) {
      throw new Error('CANNOT_GRANT_HIGHER_ROLE');
    }
    
    this.memberTree.addMember(dokoId, role, adderDokoId);
    this.emit('member:added', { dokoId, role, addedBy: adderDokoId });
    
    return true;
  }
  
  /**
   * Remove a member from the bundle
   */
  removeMember(dokoId, removerDokoId) {
    // Verify remover has permission
    if (!this.memberTree.hasRole(removerDokoId, GUMBA_ROLE.ADMIN)) {
      throw new Error('REMOVER_NOT_AUTHORIZED');
    }
    
    // Can't remove owner
    if (this.memberTree.getRole(dokoId) === GUMBA_ROLE.OWNER) {
      throw new Error('CANNOT_REMOVE_OWNER');
    }
    
    // Can't remove someone with higher/equal role (unless owner)
    const removerRole = this.memberTree.getRole(removerDokoId);
    const targetRole = this.memberTree.getRole(dokoId);
    const roleHierarchy = [GUMBA_ROLE.READER, GUMBA_ROLE.MEMBER, GUMBA_ROLE.ADMIN, GUMBA_ROLE.OWNER];
    
    if (removerRole !== GUMBA_ROLE.OWNER && 
        roleHierarchy.indexOf(targetRole) >= roleHierarchy.indexOf(removerRole)) {
      throw new Error('CANNOT_REMOVE_EQUAL_OR_HIGHER');
    }
    
    this.memberTree.removeMember(dokoId);
    this.gate.revokeAccess(dokoId);
    this.emit('member:removed', { dokoId, removedBy: removerDokoId });
    
    return true;
  }
  
  /**
   * Get bundle info (public metadata)
   */
  getInfo() {
    return {
      bundleId: this.bundleId,
      name: this.name,
      description: this.description,
      memberCount: this.memberTree.size,
      messageCount: this.metadata.messageCount,
      createdAt: this.createdAt,
      lastActivity: this.metadata.lastActivity,
    };
  }
  
  /**
   * Export bundle for backup (encrypted)
   */
  export() {
    return {
      bundleId: this.bundleId,
      name: this.name,
      description: this.description,
      ownerDokoId: this.ownerDokoId,
      metadata: this.metadata,
      members: this.memberTree.export(),
      messages: this.messages, // Still encrypted
      exportedAt: Date.now(),
    };
  }
  
  /**
   * Import bundle from backup
   */
  static import(data, ownerSecret) {
    const bundle = new GumbaBundle(data.bundleId, {
      name: data.name,
      description: data.description,
      ownerDokoId: data.ownerDokoId,
    });
    
    bundle.initialize(ownerSecret);
    bundle.memberTree.import(data.members);
    bundle.messages = data.messages;
    bundle.metadata = data.metadata;
    bundle.messageIndex = data.messages.length;
    
    return bundle;
  }
  
  /**
   * Clean up resources
   */
  destroy() {
    if (this.key) {
      this.key.destroy();
      this.key = null;
    }
    this.messages = [];
    this.removeAllListeners();
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// GUMBA HUB - Multi-bundle management
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * GumbaHub - Manages multiple GUMBA bundles on a node
 * 
 * "The monastery courtyard - where all the sacred rooms are accessed"
 */
export class GumbaHub extends EventEmitter {
  /**
   * @param {Object} identity - Node identity with signing capability
   * @param {Object} annex - ANNEX instance for secure delivery
   * @param {Object} options - Hub configuration
   */
  constructor(identity, annex, options = {}) {
    super();
    
    this.identity = identity;
    this.annex = annex;
    this.options = options;
    
    // Active bundles
    this.bundles = new Map(); // bundleId -> GumbaBundle
    
    // Access sessions
    this.sessions = new Map(); // sessionId -> { dokoId, bundleIds, expiresAt }
    
    // Public key registry (for testing/local lookups before KeyResolver integration)
    this.publicKeys = new Map(); // dokoId -> publicKey
    
    // KeyResolver: unified key resolution (attached lazily)
    this.keyResolver = options.keyResolver || null;
    
    // Stats
    this.stats = {
      bundlesCreated: 0,
      messagesProcessed: 0,
      accessAttempts: 0,
    };
    
    log.info('GumbaHub initialized');
  }
  
  /**
   * Register a DOKO public key for local lookups
   * Useful for testing or pre-cached keys
   */
  registerPublicKey(dokoId, publicKey) {
    this.publicKeys.set(dokoId, publicKey);
  }
  
  /**
   * Create a new bundle
   */
  createBundle(bundleId, options = {}) {
    if (this.bundles.has(bundleId)) {
      throw new Error('BUNDLE_EXISTS');
    }
    
    const bundle = new GumbaBundle(bundleId, {
      ...options,
      ownerDokoId: this.identity.identity.dokoId || this.identity.identity.nodeId,
    });
    
    // Initialize with node's secret
    const ownerSecret = this.identity.identity.secretKey || 
                        this._deriveOwnerSecret(bundleId);
    bundle.initialize(ownerSecret);
    
    this.bundles.set(bundleId, bundle);
    this.stats.bundlesCreated++;
    
    // Forward events
    bundle.on('message', (data) => this.emit('bundle:message', { bundleId, ...data }));
    bundle.on('member:added', (data) => this.emit('bundle:member:added', { bundleId, ...data }));
    bundle.on('member:removed', (data) => this.emit('bundle:member:removed', { bundleId, ...data }));
    
    log.info('Bundle created', { bundleId, name: options.name });
    
    return bundle.getInfo();
  }
  
  /**
   * Get a bundle by ID
   */
  getBundle(bundleId) {
    return this.bundles.get(bundleId) || null;
  }
  
  /**
   * List all bundles (public info only)
   */
  listBundles() {
    return Array.from(this.bundles.values()).map(b => b.getInfo());
  }
  
  /**
   * Handle access request
   * 
   * Flow:
   * 1. Visitor presents proof
   * 2. Gate verifies proof
   * 3. If granted, create session + deliver via ANNEX
   */
  async handleAccessRequest(bundleId, proof, visitorNodeId) {
    this.stats.accessAttempts++;
    
    const bundle = this.bundles.get(bundleId);
    if (!bundle) {
      return { granted: false, reason: 'BUNDLE_NOT_FOUND' };
    }
    
    // Verify access
    const accessResult = await bundle.gate.verifyAccess(proof, async (dokoId) => {
      // Get public key from mesh/KHATA
      return this._getDokoPublicKey(dokoId);
    });
    
    if (!accessResult.granted) {
      log.debug('Access denied', { bundleId, reason: accessResult.reason });
      return accessResult;
    }
    
    // Create session
    const sessionId = bytesToHex(randomBytes(16));
    this.sessions.set(sessionId, {
      dokoId: accessResult.dokoId,
      role: accessResult.role,
      bundleId,
      visitorNodeId,
      createdAt: Date.now(),
      expiresAt: Date.now() + GUMBA_CONFIG.proofCacheTime,
    });
    
    log.info('Access granted', { 
      bundleId, 
      dokoId: accessResult.dokoId?.slice(0, 16),
      role: accessResult.role,
    });
    
    return {
      granted: true,
      sessionId,
      role: accessResult.role,
      bundleInfo: bundle.getInfo(),
    };
  }
  
  /**
   * Get messages for an active session
   */
  async getMessages(sessionId, options = {}) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return { error: 'SESSION_NOT_FOUND' };
    }
    
    if (Date.now() > session.expiresAt) {
      this.sessions.delete(sessionId);
      return { error: 'SESSION_EXPIRED' };
    }
    
    const bundle = this.bundles.get(session.bundleId);
    if (!bundle) {
      return { error: 'BUNDLE_NOT_FOUND' };
    }
    
    // Get messages (decrypted locally)
    const accessResult = { granted: true, role: session.role };
    const result = bundle.getMessages(accessResult, options);
    
    this.stats.messagesProcessed += result.count;
    
    // Deliver via ANNEX for E2E encryption to remote visitor
    if (this.annex && session.visitorNodeId) {
      try {
        await this.annex.send(session.visitorNodeId, {
          type: 'gumba:messages',
          sessionId,
          bundleId: session.bundleId,
          ...result,
        });
        return { delivered: true, via: 'annex', count: result.count };
      } catch (err) {
        log.warn('ANNEX delivery failed, returning plaintext', {
          visitor: session.visitorNodeId.slice(0, 16),
          error: err.message,
        });
        // Fall through to direct return
      }
    }
    
    return result;
  }
  
  /**
   * Post a message to a bundle
   */
  async postMessage(sessionId, content) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return { error: 'SESSION_NOT_FOUND' };
    }
    
    if (Date.now() > session.expiresAt) {
      this.sessions.delete(sessionId);
      return { error: 'SESSION_EXPIRED' };
    }
    
    const bundle = this.bundles.get(session.bundleId);
    if (!bundle) {
      return { error: 'BUNDLE_NOT_FOUND' };
    }
    
    try {
      const result = bundle.addMessage(content, session.dokoId);
      return { success: true, ...result };
    } catch (err) {
      return { error: err.message };
    }
  }
  
  /**
   * Issue a challenge for a bundle
   */
  issueChallenge(bundleId, requesterDokoId) {
    const bundle = this.bundles.get(bundleId);
    if (!bundle) {
      return { error: 'BUNDLE_NOT_FOUND' };
    }
    
    return bundle.gate.issueChallenge(bundleId, requesterDokoId);
  }
  
  /**
   * Delete a bundle
   */
  deleteBundle(bundleId, requesterDokoId) {
    const bundle = this.bundles.get(bundleId);
    if (!bundle) {
      return { error: 'BUNDLE_NOT_FOUND' };
    }
    
    // Only owner can delete
    if (!bundle.memberTree.hasRole(requesterDokoId, GUMBA_ROLE.OWNER)) {
      return { error: 'NOT_AUTHORIZED' };
    }
    
    bundle.destroy();
    this.bundles.delete(bundleId);
    
    // Invalidate related sessions
    for (const [sessionId, session] of this.sessions) {
      if (session.bundleId === bundleId) {
        this.sessions.delete(sessionId);
      }
    }
    
    log.info('Bundle deleted', { bundleId });
    return { success: true };
  }
  
  /**
   * Get hub statistics
   */
  getStats() {
    return {
      ...this.stats,
      activeBundles: this.bundles.size,
      activeSessions: this.sessions.size,
    };
  }
  
  /**
   * Derive owner secret for a bundle
   * Uses node identity to derive deterministic secret
   */
  _deriveOwnerSecret(bundleId) {
    return createHash('sha3-256')
      .update('GUMBA-OWNER')
      .update(this.identity.identity.nodeId)
      .update(bundleId)
      .digest();
  }
  
  /**
   * Get DOKO public key — unified resolution cascade
   * 
   * Resolution order:
   *   1. Local publicKeys map (test/pre-cached)
   *   2. Own identity
   *   3. KeyResolver (DOKO cache, peers, SHERPA, etc.)
   */
  async _getDokoPublicKey(dokoId) {
    // Check local registry first (backwards compat)
    if (this.publicKeys.has(dokoId)) {
      return this.publicKeys.get(dokoId);
    }
    
    // Check if it's our own identity
    if (this.identity.identity.dokoId === dokoId) {
      return this.identity.identity.publicKey;
    }
    
    // KeyResolver: unified key resolution
    if (this.keyResolver) {
      const key = this.keyResolver.resolve(dokoId);
      if (key) return key;
    }
    
    log.warn('DOKO public key not found', { dokoId: dokoId.slice(0, 16) });
    return null;
  }
  
  /**
   * Cleanup expired sessions
   */
  cleanupSessions() {
    const now = Date.now();
    let cleaned = 0;
    
    for (const [sessionId, session] of this.sessions) {
      if (now > session.expiresAt) {
        this.sessions.delete(sessionId);
        cleaned++;
      }
    }
    
    if (cleaned > 0) {
      log.debug('Cleaned expired sessions', { count: cleaned });
    }
    
    return cleaned;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export default {
  GumbaKey,
  GumbaMemberTree,
  GumbaProof,
  GumbaGate,
  GumbaBundle,
  GumbaHub,
  GUMBA_CONFIG,
  GUMBA_PROOF_TYPE,
  GUMBA_ROLE,
};
