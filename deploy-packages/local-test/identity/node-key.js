/**
 * Yakmesh Node Identity - Post-Quantum Secure
 * Uses ML-DSA-65 (Dilithium3) from FIPS 204
 * 
 * Security Level: NIST Level 3 (~192-bit classical security)
 * Quantum Resistant: Yes (lattice-based)
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * ⚠️  SECURITY ARCHITECTURE - DO NOT MODIFY WITHOUT EXPLICIT REVIEW  ⚠️
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * IMPORTANT: Node IDs are composed of TWO parts:
 * 1. NETWORK NAME - Derived from codebase hash (SAME for all nodes on network)
 * 2. INSTANCE ID - Derived from public key hash (UNIQUE per node instance)
 * 
 * This design ensures:
 * - Nodes running identical code share the same network name
 * - Each node instance has a unique identifier
 * - Human-readable verification: same network name = same code = can peer
 * - Codebase integrity is cryptographically bound to identity
 * 
 * Format: "node-[network-name]-[instance-id]"
 * Example: "node-qubit-lattice-prism-pq-a7x9"
 *          ^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^
 *          Same for all nodes    Unique per instance
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * 🚫 REJECTED SIMPLIFICATIONS (Security Anti-Patterns):
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * The following "simplifications" have been proposed and MUST BE REJECTED:
 * 
 * ❌ NodeID = SHA3-256(publicKey)
 *    WHY REJECT: Removes codebase integrity verification. A malicious node
 *    running modified code would be indistinguishable from honest nodes.
 * 
 * ❌ NodeID = base64(publicKey)
 *    WHY REJECT: Same as above, plus loses human-readable verification.
 * 
 * ❌ NodeID = UUID or random string
 *    WHY REJECT: Breaks deterministic derivation. Cannot verify identity
 *    matches public key. Enables identity spoofing.
 * 
 * ❌ Removing the codebase hash component
 *    WHY REJECT: Fundamental to network segmentation by code version.
 *    Prevents incompatible or malicious code from joining honest networks.
 * 
 * The current two-part design (network + instance) via iO obfuscation is
 * INTENTIONAL and provides security properties that simpler schemes lack.
 * 
 * This warning added 2026-01-18 after a spec draft attempted to simplify
 * NodeID to just SHA3-256(publicKey), which would have undermined the
 * entire network integrity model.
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * @module identity/node-key
 * @version 2.0.0 — Two-Layer Deterministic Identity
 */

import { createLogger } from '../utils/logger.js';

const log = createLogger('identity:node-key');

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_256 as _nobleSha3 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, unlinkSync } from 'fs';
import { join } from 'path';
import { randomBytes } from 'crypto';
import { platform } from 'os';

// ACCEL: Hardware-accelerated crypto (native SHA3 via OpenSSL/SHA-NI, future liboqs)
import { sha3_256, mlDsa65Sign, mlDsa65Verify } from '../utils/accel.js';

// Import iO network identity for obfuscated node IDs
import { deriveNetworkName, deriveNetworkId, deriveVerificationPhrase } from '../oracle/network-identity.js';

// SLH-DSA (FIPS 205) backup signature — defense-in-depth against lattice breaks
import {
  generateBackupSignatureKeyPair,
  signBackup as slhDsaSign,
  verifyBackup as slhDsaVerify,
} from '../security/crypto-config.js';

// Two-Layer Identity: Machine seed + deterministic derivation
import { MachineSeed, deriveNodeSecret, deriveBackupSecret } from './machine-seed.js';

// Cached codebase hash - set during first identity generation
let cachedCodebaseHash = null;

/**
 * Set the codebase hash for node identity generation
 * This MUST be called before generating any node IDs
 * 
 * @param {string} hash - The codebase hash from the validation oracle
 */
export function setCodebaseHash(hash) {
  if (cachedCodebaseHash && cachedCodebaseHash !== hash) {
    console.warn('⚠️ Codebase hash changed - network identity will change!');
  }
  cachedCodebaseHash = hash;
}

/**
 * Get the current codebase hash
 * @returns {string|null} The codebase hash or null if not set
 */
export function getCodebaseHash() {
  return cachedCodebaseHash;
}

/**
 * Generate a node ID using iO obfuscation
 * 
 * The node ID is composed of:
 * 1. Network name - derived from CODEBASE hash (same for all nodes on network)
 * 2. Instance ID - derived from PUBLIC KEY hash (unique per node)
 * 
 * @param {Uint8Array} publicKey - The node's public key
 * @param {string} codebaseHash - The codebase hash (optional, uses cached if not provided)
 * @returns {string} Node ID like "node-qubit-lattice-prism-pq-a7x9"
 */
export function generateNodeId(publicKey, codebaseHash = null) {
  const effectiveCodebaseHash = codebaseHash || cachedCodebaseHash;
  
  if (!effectiveCodebaseHash) {
    throw new Error(
      'Codebase hash not set! Call setCodebaseHash() with the oracle\'s selfHash ' +
      'before generating node identities. This ensures all nodes on the same ' +
      'network share the same network name.'
    );
  }
  
  // NETWORK NAME: Derived from codebase hash
  // This is the SAME for all nodes running identical code
  const networkName = deriveNetworkName(effectiveCodebaseHash, 3);
  
  // INSTANCE ID: Derived from public key hash  
  // This is UNIQUE per node instance
  const publicKeyHash = sha3_256(publicKey);
  const publicKeyHashHex = bytesToHex(publicKeyHash);
  const instanceId = deriveNetworkId(publicKeyHashHex);
  
  // Format: "node-[network-name]-[instance-id]"
  // e.g., "node-qubit-lattice-prism-pq-a7x9"
  return `node-${networkName}-${instanceId}`;
}

/**
 * Generate internal hash for private operations (NOT exposed externally)
 * This is kept for signature verification and internal lookups
 */
export function generateInternalHash(publicKey) {
  const hash = sha3_256(publicKey);
  return bytesToHex(hash.slice(0, 16));
}

/**
 * Generate ML-DSA-65 (Dilithium3) keypair for node identity.
 * 
 * v2.0: Accepts an optional deterministic seed. When provided, the keypair
 * is fully deterministic — same seed always produces the same keys.
 * When omitted, falls back to random generation (for testing/standalone use).
 * 
 * @param {Uint8Array} [deterministicSeed] - 32-byte seed from HKDF derivation
 * @returns {{ publicKey: string, secretKey: string, algorithm: string, nistLevel: number }}
 */
export function generateKeyPair(deterministicSeed = null) {
  const seed = deterministicSeed || crypto.getRandomValues(new Uint8Array(32));
  const keyPair = ml_dsa65.keygen(seed);
  return {
    publicKey: bytesToHex(keyPair.publicKey),
    secretKey: bytesToHex(keyPair.secretKey),
    algorithm: 'ML-DSA-65',
    nistLevel: 3,
    deterministic: !!deterministicSeed,
  };
}

/**
 * Sign a message with the node's secret key
 */
export function signMessage(message, secretKeyHex) {
  const secretKey = hexToBytes(secretKeyHex);
  const messageBytes = typeof message === 'string' 
    ? new TextEncoder().encode(message)
    : message;
  // ml_dsa65.sign takes (message, secretKey) — ACCEL-accelerated
  const signature = mlDsa65Sign(messageBytes, secretKey);
  return bytesToHex(signature);
}

/**
 * Verify a signature from another node
 */
export function verifySignature(message, signatureHex, publicKeyHex) {
  try {
    const publicKey = hexToBytes(publicKeyHex);
    const signature = hexToBytes(signatureHex);
    const messageBytes = typeof message === 'string'
      ? new TextEncoder().encode(message)
      : message;
    // ml_dsa65.verify takes (signature, message, publicKey) — ACCEL-accelerated
    return mlDsa65Verify(signature, messageBytes, publicKey);
  } catch (e) {
    console.error('Signature verification failed:', e.message);
    return false;
  }
}

/**
 * Node Identity Manager
 * Handles persistent storage and management of node identity
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * v2.0 — TWO-LAYER DETERMINISTIC IDENTITY
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * The oracle MUST be initialized before creating node identities.
 * 
 * Layer 1 (Network): oracleHash → networkName, networkId, verPhrase  (SHARED)
 * Layer 2 (Node):    seed + oracleHash + verPhrase → HKDF → keypair  (UNIQUE)
 * 
 * Private keys are NEVER stored on disk. They are derived fresh each startup
 * from the machine seed + codebase hash + verification phrase.
 * ═══════════════════════════════════════════════════════════════════════════════
 */
export class NodeIdentity {
  constructor(dataDir = './data') {
    this.dataDir = dataDir;
    this.keyPath = join(dataDir, 'node-key.json');  // Public identity file
    this.identity = null;
    this.networkName = null;
    this.verificationPhrase = null;
    this.machineSeed = new MachineSeed(dataDir);     // Layer 2 anchor
  }

  /**
   * Set restrictive file permissions on key file (owner read/write only).
   * On Windows this is a no-op (NTFS ACLs handle access differently).
   */
  _secureKeyFile() {
    if (platform() !== 'win32') {
      try {
        chmodSync(this.keyPath, 0o600); // rw------- (owner only)
      } catch (e) {
        log.warn('Could not set restrictive permissions on key file', { error: e.message });
      }
    }
  }

  /**
   * Initialize or load node identity using two-layer deterministic derivation.
   * 
   * Flow:
   * 1. Get oracleHash → derive Layer 1 (networkName, verPhrase)
   * 2. Load/create machine seed (Layer 2 anchor)
   * 3. HKDF(seed, oracleHash, verPhrase) → deterministic keypair
   * 4. Record migration entry (seed + oracleHash → pubKeyHash)
   * 5. Store public identity to disk (private key stays in memory only)
   * 
   * @param {string} nodeName - Human-readable node name
   * @param {string} region - Node region/location
   * @param {Object} oracle - The validation oracle instance (provides codebase hash)
   */
  async init(nodeName = 'Yakmesh Node', region = 'local', oracle = null) {
    // Ensure data directory exists
    if (!existsSync(this.dataDir)) {
      mkdirSync(this.dataDir, { recursive: true });
    }

    // ─── Layer 1: Network Identity (shared, code-derived) ───
    let codebaseHash = cachedCodebaseHash;
    if (oracle) {
      const proof = oracle.generateCodeProof();
      codebaseHash = proof.selfHash;
      setCodebaseHash(codebaseHash);
    }

    if (!codebaseHash) {
      throw new Error(
        'Cannot initialize identity: codebase hash not available. ' +
        'Pass the oracle instance to init() or call setCodebaseHash() first.'
      );
    }

    this.networkName = deriveNetworkName(codebaseHash, 3);
    this.verificationPhrase = deriveVerificationPhrase(codebaseHash);

    // ─── Layer 2: Machine Seed (unique, hardware-bound) ───
    await this.machineSeed.init();

    // ─── Legacy migration: detect old encrypted-private-key format ───
    if (existsSync(this.keyPath)) {
      const oldData = JSON.parse(readFileSync(this.keyPath, 'utf8'));
      if (oldData.secretKeyEnc || oldData.secretKey) {
        log.warn('═══════════════════════════════════════════════════════════');
        log.warn('LEGACY IDENTITY DETECTED — migrating to two-layer system');
        log.warn('Old format: encrypted private key on disk');
        log.warn('New format: deterministic derivation from machine seed');
        log.warn('Old node-key.json will be archived as node-key.legacy.json');
        log.warn('═══════════════════════════════════════════════════════════');
        const legacyPath = join(this.dataDir, 'node-key.legacy.json');
        writeFileSync(legacyPath, JSON.stringify(oldData, null, 2));
        unlinkSync(this.keyPath);
      }
    }

    // ─── Derive keypair deterministically ───
    const seed = this.machineSeed.getSeed();
    const nodeSecret = deriveNodeSecret(seed, codebaseHash, this.verificationPhrase);
    const keyPair = generateKeyPair(nodeSecret);

    const publicKeyBytes = hexToBytes(keyPair.publicKey);
    const nodeId = generateNodeId(publicKeyBytes, codebaseHash);
    const pubKeyHash = bytesToHex(sha3_256(publicKeyBytes));

    // ─── Derive SLH-DSA backup keypair deterministically ───
    const backupSecret = deriveBackupSecret(seed, codebaseHash, this.verificationPhrase);
    // SLH-DSA keygen uses the first 32 bytes as seed material
    const backupKeyPair = generateBackupSignatureKeyPair(backupSecret);
    const backupPublicKeyHex = bytesToHex(backupKeyPair.publicKey);
    const backupSecretKeyHex = bytesToHex(backupKeyPair.secretKey);

    // ─── Record migration entry ───
    this.machineSeed.recordMigration(codebaseHash, pubKeyHash, this.networkName);

    // ─── Build in-memory identity (private keys NEVER touch disk) ───
    this.identity = {
      nodeId,
      networkName: this.networkName,
      verificationPhrase: this.verificationPhrase,
      codebaseHash,
      name: nodeName,
      region,
      publicKey: keyPair.publicKey,
      secretKey: keyPair.secretKey,          // IN MEMORY ONLY — derived, not stored
      backupPublicKey: backupPublicKeyHex,
      backupSecretKey: backupSecretKeyHex,   // IN MEMORY ONLY — derived, not stored
      algorithm: keyPair.algorithm,
      backupAlgorithm: 'SLH-DSA-SHA2-192f',
      nistLevel: keyPair.nistLevel,
      deterministic: true,
      createdAt: Date.now(),
      capabilities: ['listings', 'chat', 'forum', 'qcoa'],
    };

    // ─── Store PUBLIC identity to disk (no secrets!) ───
    const toStore = {
      nodeId,
      networkName: this.networkName,
      verificationPhrase: this.verificationPhrase,
      codebaseHash,
      name: nodeName,
      region,
      publicKey: keyPair.publicKey,
      backupPublicKey: backupPublicKeyHex,
      algorithm: keyPair.algorithm,
      backupAlgorithm: 'SLH-DSA-SHA2-192f',
      nistLevel: keyPair.nistLevel,
      deterministic: true,
      migrationEntries: this.machineSeed.getMigrationChain().length,
      createdAt: Date.now(),
    };
    writeFileSync(this.keyPath, JSON.stringify(toStore, null, 2));
    this._secureKeyFile();

    // ─── Log identity info ───
    const migrationChain = this.machineSeed.getMigrationChain();
    const isNewNetwork = this.machineSeed.isFirstRun() || migrationChain.length <= 1;
    const previousId = this.machineSeed.getPreviousIdentity();

    log.info(isNewNetwork ? 'Generated new deterministic identity' : 'Derived identity for network version', {
      nodeId,
      network: this.networkName,
      algorithm: 'ML-DSA-65 (FIPS 204, NIST Level 3)',
      backupAlgorithm: 'SLH-DSA-SHA2-192f (FIPS 205)',
      derivation: 'HKDF-SHA3-256(seed + oracleHash + verPhrase)',
      privateKeysOnDisk: false,
      migrationChainLength: migrationChain.length,
      previousNetwork: previousId?.networkName || 'none (first run)',
      verificationPhrase: this.verificationPhrase,
    });

    return this.identity;
  }

  /**
   * Get public identity (safe to share with other nodes)
   * Includes network identity for peer verification
   */
  getPublicIdentity() {
    if (!this.identity) throw new Error('Identity not initialized');
    
    return {
      nodeId: this.identity.nodeId,
      networkName: this.identity.networkName || this.networkName,
      verificationPhrase: this.identity.verificationPhrase || this.verificationPhrase,
      name: this.identity.name,
      region: this.identity.region,
      publicKey: this.identity.publicKey,
      backupPublicKey: this.identity.backupPublicKey || null,  // SLH-DSA (FIPS 205)
      algorithm: this.identity.algorithm,
      backupAlgorithm: this.identity.backupAlgorithm || null,
      nistLevel: this.identity.nistLevel,
      capabilities: this.identity.capabilities,
      createdAt: this.identity.createdAt,
    };
  }
  
  /**
   * Get network identity info (for human verification)
   * All nodes on the same network should have matching values
   */
  getNetworkIdentity() {
    return {
      networkName: this.identity?.networkName || this.networkName,
      verificationPhrase: this.identity?.verificationPhrase || this.verificationPhrase,
    };
  }

  /**
   * Get the migration chain — history of this seed's identities across network versions.
   * @returns {Object[]} Array of { oracleHash, pubKeyHash, networkName, timestamp }
   */
  getMigrationChain() {
    return this.machineSeed.getMigrationChain();
  }

  /**
   * Generate a migration proof that cryptographically links the current identity
   * to the previous identity on the migration chain.
   * 
   * Both signatures together prove the same physical entity (seed) controls
   * both identities — without revealing the seed.
   * 
   * Peers verify: ML-DSA-65.verify(sigOld, "MIGRATE:"+newPubKey, oldPubKey)
   *               ML-DSA-65.verify(sigNew, "MIGRATE:"+oldPubKey, newPubKey)
   * 
   * @param {string} oldOracleHash - Oracle hash of the previous network version
   * @param {string} oldVerPhrase - Verification phrase of the previous network
   * @returns {{ oldPubKey: string, newPubKey: string, sigOld: string, sigNew: string, timestamp: number } | null}
   */
  generateMigrationProof(oldOracleHash, oldVerPhrase) {
    if (!this.identity) throw new Error('Identity not initialized');
    
    const seed = this.machineSeed.getSeed();
    
    // Derive the OLD keypair from the same seed + old oracle hash
    const oldSecret = deriveNodeSecret(seed, oldOracleHash, oldVerPhrase);
    const oldKeyPair = generateKeyPair(oldSecret);
    
    const newPubKey = this.identity.publicKey;
    const timestamp = Date.now();
    
    // Sign with OLD key: "I (old identity) vouch for this new identity"
    const migrateMsg1 = `MIGRATE:${newPubKey}:${timestamp}`;
    const sigOld = signMessage(migrateMsg1, oldKeyPair.secretKey);
    
    // Sign with NEW key: "I (new identity) claim this old identity"
    const migrateMsg2 = `MIGRATE:${oldKeyPair.publicKey}:${timestamp}`;
    const sigNew = signMessage(migrateMsg2, this.identity.secretKey);
    
    return {
      oldPubKey: oldKeyPair.publicKey,
      newPubKey,
      sigOld,
      sigNew,
      timestamp,
      oldNetwork: deriveNetworkName(oldOracleHash, 3),
      newNetwork: this.networkName,
    };
  }

  /**
   * Verify a migration proof from another node.
   * 
   * @param {Object} proof - The migration proof object
   * @returns {{ valid: boolean, oldValid: boolean, newValid: boolean }}
   */
  static verifyMigrationProof(proof) {
    const { oldPubKey, newPubKey, sigOld, sigNew, timestamp } = proof;
    
    const migrateMsg1 = `MIGRATE:${newPubKey}:${timestamp}`;
    const migrateMsg2 = `MIGRATE:${oldPubKey}:${timestamp}`;
    
    const oldValid = verifySignature(migrateMsg1, sigOld, oldPubKey);
    const newValid = verifySignature(migrateMsg2, sigNew, newPubKey);
    
    return {
      valid: oldValid && newValid,
      oldValid,
      newValid,
    };
  }

  /**
   * Sign a message with this node's identity
   */
  sign(message) {
    if (!this.identity) throw new Error('Identity not initialized');
    return signMessage(message, this.identity.secretKey);
  }

  /**
   * Verify a message signature from another node
   */
  verify(message, signature, publicKey) {
    return verifySignature(message, signature, publicKey);
  }

  /**
   * Sign a JSON object (for mesh protocol messages)
   */
  signObject(obj) {
    const payload = JSON.stringify(obj);
    return {
      ...obj,
      _signature: this.sign(payload),
      _signer: this.identity.nodeId,
      _signedAt: Date.now(),
    };
  }

  /**
   * Verify a signed object from another node
   */
  verifyObject(signedObj, publicKey) {
    const { _signature, _signer, _signedAt, ...obj } = signedObj;
    const payload = JSON.stringify(obj);
    return this.verify(payload, _signature, publicKey);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SLH-DSA Dual Signature — Defense-in-Depth for Critical Operations
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // Critical ops (content publish, identity registration, relay registration)
  // produce BOTH an ML-DSA-65 signature (fast, lattice-based) AND an SLH-DSA
  // signature (slower ~100-160ms, hash-based). An attacker must break BOTH
  // lattice AND hash assumptions to forge a critical signature.
  //
  // Non-critical ops (regular messages, peer auth) continue using ML-DSA-65
  // only for performance.
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Check if this node has SLH-DSA dual-sig capability
   * @returns {boolean}
   */
  hasDualSignature() {
    return !!(this.identity?.backupSecretKey && this.identity?.backupPublicKey);
  }

  /**
   * Sign a critical message with BOTH ML-DSA-65 AND SLH-DSA (defense-in-depth)
   * 
   * Use for: content publish, identity registration, relay registration,
   * revocation certificates — any operation worth the ~100-160ms cost.
   * 
   * @param {string} message - Message to sign (string)
   * @returns {{ primary: string, backup: string }} Both signatures as hex strings
   * @throws {Error} If backup key not available
   */
  signCritical(message) {
    if (!this.identity) throw new Error('Identity not initialized');
    if (!this.identity.backupSecretKey) {
      throw new Error('SLH-DSA backup key not available — cannot create dual signature');
    }

    const messageBytes = typeof message === 'string'
      ? new TextEncoder().encode(message)
      : message;

    // ML-DSA-65 primary signature (fast, ~1ms)
    const primarySig = this.sign(message);

    // SLH-DSA backup signature (slower, ~100-160ms, but hash-based security)
    const backupSecretKey = hexToBytes(this.identity.backupSecretKey);
    const backupSig = slhDsaSign(messageBytes, backupSecretKey);

    return {
      primary: primarySig,
      backup: bytesToHex(backupSig),
    };
  }

  /**
   * Verify a dual signature from another node (BOTH must be valid)
   * 
   * @param {string} message - Original message
   * @param {string} primarySigHex - ML-DSA-65 signature (hex)
   * @param {string} backupSigHex - SLH-DSA signature (hex)
   * @param {string} primaryPKHex - ML-DSA-65 public key (hex)
   * @param {string} backupPKHex - SLH-DSA public key (hex)
   * @returns {{ valid: boolean, primaryValid: boolean, backupValid: boolean }}
   */
  verifyCritical(message, primarySigHex, backupSigHex, primaryPKHex, backupPKHex) {
    const messageBytes = typeof message === 'string'
      ? new TextEncoder().encode(message)
      : message;

    // Verify ML-DSA-65 (primary)
    const primaryValid = this.verify(message, primarySigHex, primaryPKHex);

    // Verify SLH-DSA (backup)
    let backupValid = false;
    try {
      const backupSig = hexToBytes(backupSigHex);
      const backupPK = hexToBytes(backupPKHex);
      backupValid = slhDsaVerify(backupSig, messageBytes, backupPK);
    } catch (e) {
      log.error('SLH-DSA backup verification failed', { error: e.message });
    }

    return {
      valid: primaryValid && backupValid,
      primaryValid,
      backupValid,
    };
  }

  /**
   * Sign a JSON object with dual signature (for critical mesh protocol messages)
   * @param {Object} obj - Object to sign
   * @returns {Object} Object with _signature, _backupSignature, _signer, _signedAt
   */
  signCriticalObject(obj) {
    const payload = JSON.stringify(obj);
    const sigs = this.signCritical(payload);
    return {
      ...obj,
      _signature: sigs.primary,
      _backupSignature: sigs.backup,
      _signer: this.identity.nodeId,
      _signedAt: Date.now(),
    };
  }

  /**
   * Verify a dual-signed object from another node
   * @param {Object} signedObj - Object with _signature and _backupSignature
   * @param {string} primaryPK - ML-DSA-65 public key (hex)
   * @param {string} backupPK - SLH-DSA public key (hex)
   * @returns {{ valid: boolean, primaryValid: boolean, backupValid: boolean }}
   */
  verifyCriticalObject(signedObj, primaryPK, backupPK) {
    const { _signature, _backupSignature, _signer, _signedAt, ...obj } = signedObj;
    const payload = JSON.stringify(obj);
    return this.verifyCritical(payload, _signature, _backupSignature, primaryPK, backupPK);
  }
}

export default NodeIdentity;
