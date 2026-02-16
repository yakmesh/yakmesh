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
 * @version 1.6.0
 */

import { createLogger } from '../utils/logger.js';

const log = createLogger('identity:node-key');

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_256 as _nobleSha3 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from 'fs';
import { join } from 'path';
import { createCipheriv, createDecipheriv, scryptSync, randomBytes } from 'crypto';
import { hostname, platform } from 'os';

// ACCEL: Hardware-accelerated crypto (native SHA3 via OpenSSL/SHA-NI, future liboqs)
import { sha3_256, mlDsa65Sign, mlDsa65Verify } from '../utils/accel.js';

// Import iO network identity for obfuscated node IDs
import { deriveNetworkName, deriveNetworkId } from '../oracle/network-identity.js';

// SLH-DSA (FIPS 205) backup signature — defense-in-depth against lattice breaks
import {
  generateBackupSignatureKeyPair,
  signBackup as slhDsaSign,
  verifyBackup as slhDsaVerify,
} from '../security/crypto-config.js';

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
 * Generate ML-DSA-65 (Dilithium3) keypair for node identity
 * This is NIST FIPS 204 standardized post-quantum signature
 */
export function generateKeyPair() {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const keyPair = ml_dsa65.keygen(seed);
  return {
    publicKey: bytesToHex(keyPair.publicKey),
    secretKey: bytesToHex(keyPair.secretKey),
    algorithm: 'ML-DSA-65',
    nistLevel: 3,
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
 * IMPORTANT: The oracle must be initialized before creating node identities
 * to ensure the codebase hash is available for network name derivation.
 */
export class NodeIdentity {
  constructor(dataDir = './data') {
    this.dataDir = dataDir;
    this.keyPath = join(dataDir, 'node-key.json');
    this.identity = null;
    this.networkName = null;
    this.verificationPhrase = null;
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
   * Derive a machine-specific encryption key for secret key storage.
   * 
   * PASSPHRASE: Pre-iO node material (codebaseHash + SHA3-256(publicKey))
   *   - Cryptographically bound to the codebase (wrong code = wrong key)
   *   - Cryptographically bound to the keypair (wrong node = wrong key)
   *   - NOT publicly exposed (the iO-obfuscated nodeId is what peers see)
   * 
   * SALT: Machine-bound context (hostname + dataDir)
   *   - Key file is useless if copied to another machine or directory
   * 
   * Combined: attacker needs exact machine + exact codebase + exact public key
   * to derive the decryption key. Three independent axes of binding.
   * 
   * @param {string} publicKeyHex - The node's public key (hex)
   * @param {string} codebaseHash - The codebase hash from the oracle
   */
  _deriveStorageKey(publicKeyHex, codebaseHash) {
    // Pre-iO material: the raw cryptographic inputs BEFORE iO obfuscation
    // This is the codebase hash + public key hash — not the public nodeId
    const publicKeyHash = bytesToHex(sha3_256(hexToBytes(publicKeyHex)));
    const passphrase = `${codebaseHash}:${publicKeyHash}`;
    
    const machineContext = `yakmesh:node-key:${hostname()}:${this.dataDir}`;
    const salt = sha3_256(new TextEncoder().encode(machineContext));
    // scrypt: N=2^14, r=8, p=1, 32-byte key
    return scryptSync(passphrase, Buffer.from(salt), 32, {
      N: 16384, r: 8, p: 1,
    });
  }

  /**
   * Encrypt the secret key for at-rest storage.
   * Returns { ciphertext, nonce, tag } all hex-encoded.
   * 
   * @param {string} secretKeyHex - The secret key to encrypt
   * @param {string} publicKeyHex - The node's public key (for key derivation)
   * @param {string} codebaseHash - The codebase hash (for key derivation)
   */
  _encryptSecretKey(secretKeyHex, publicKeyHex, codebaseHash) {
    const key = this._deriveStorageKey(publicKeyHex, codebaseHash);
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    const encrypted = Buffer.concat([
      cipher.update(secretKeyHex, 'utf8'),
      cipher.final(),
    ]);
    return {
      ciphertext: encrypted.toString('hex'),
      nonce: nonce.toString('hex'),
      tag: cipher.getAuthTag().toString('hex'),
    };
  }

  /**
   * Decrypt the secret key from at-rest storage.
   * @param {{ ciphertext: string, nonce: string, tag: string }} enc
   * @param {string} publicKeyHex - The node's public key (for key derivation)
   * @param {string} codebaseHash - The codebase hash (for key derivation)
   * @returns {string} The secret key hex string
   */
  _decryptSecretKey(enc, publicKeyHex, codebaseHash) {
    const key = this._deriveStorageKey(publicKeyHex, codebaseHash);
    const decipher = createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(enc.nonce, 'hex'),
    );
    decipher.setAuthTag(Buffer.from(enc.tag, 'hex'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(enc.ciphertext, 'hex')),
      decipher.final(),
    ]);
    return decrypted.toString('utf8');
  }

  /**
   * Initialize or load node identity
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

    // Get codebase hash from oracle if provided
    let codebaseHash = cachedCodebaseHash;
    if (oracle) {
      const proof = oracle.generateCodeProof();
      codebaseHash = proof.selfHash;
      setCodebaseHash(codebaseHash);
      
      // Import and store network identity info
      const { deriveVerificationPhrase } = await import('../oracle/network-identity.js');
      this.networkName = deriveNetworkName(codebaseHash, 3);
      this.verificationPhrase = deriveVerificationPhrase(codebaseHash);
    }

    // Load existing identity or generate new one
    if (existsSync(this.keyPath)) {
      const data = JSON.parse(readFileSync(this.keyPath, 'utf8'));
      this.identity = data;
      
      // Decrypt secret key if stored encrypted
      // Uses pre-iO material (codebaseHash + publicKey hash) as passphrase
      const storedCodebaseHash = this.identity.codebaseHash || codebaseHash;
      if (this.identity.secretKeyEnc && !this.identity.secretKey) {
        if (!storedCodebaseHash) {
          throw new Error('Cannot decrypt secret key: codebase hash not available. Pass oracle to init().');
        }
        try {
          this.identity.secretKey = this._decryptSecretKey(
            this.identity.secretKeyEnc, this.identity.publicKey, storedCodebaseHash
          );
        } catch (e) {
          log.error('Failed to decrypt secret key (wrong machine, codebase, or corrupted file)', { error: e.message });
          throw new Error('Cannot decrypt node secret key. Wrong machine, different codebase, or file corrupted.');
        }
      } else if (this.identity.secretKey && !this.identity.secretKeyEnc) {
        // Migrate plaintext key to encrypted storage
        if (storedCodebaseHash) {
          log.info('Migrating plaintext secret key to encrypted storage');
          const enc = this._encryptSecretKey(
            this.identity.secretKey, this.identity.publicKey, storedCodebaseHash
          );
          const toStore = { ...this.identity, secretKeyEnc: enc };
          delete toStore.secretKey;
          writeFileSync(this.keyPath, JSON.stringify(toStore, null, 2));
          this._secureKeyFile();
        } else {
          log.warn('Skipping secret key encryption: codebase hash not yet available');
        }
      }

      // ─── SLH-DSA Backup Key Loading / Migration ───
      // Decrypt SLH-DSA backup secret key if present
      if (this.identity.backupSecretKeyEnc && !this.identity.backupSecretKey) {
        if (storedCodebaseHash) {
          try {
            this.identity.backupSecretKey = this._decryptSecretKey(
              this.identity.backupSecretKeyEnc, this.identity.publicKey, storedCodebaseHash
            );
          } catch (e) {
            log.error('Failed to decrypt SLH-DSA backup key', { error: e.message });
            // Non-fatal: node can still operate with ML-DSA only
            log.warn('SLH-DSA backup signatures unavailable this session');
          }
        }
      } else if (!this.identity.backupPublicKey && storedCodebaseHash) {
        // Migration: existing identity has no SLH-DSA backup key — generate one
        log.info('Migrating identity: generating SLH-DSA backup keypair');
        const backupKeyPair = generateBackupSignatureKeyPair();
        this.identity.backupPublicKey = bytesToHex(backupKeyPair.publicKey);
        this.identity.backupSecretKey = bytesToHex(backupKeyPair.secretKey);
        this.identity.backupAlgorithm = 'SLH-DSA-SHA2-192f';

        // Re-save with encrypted backup key
        const backupSecretKeyEnc = this._encryptSecretKey(
          this.identity.backupSecretKey, this.identity.publicKey, storedCodebaseHash
        );
        const data = JSON.parse(readFileSync(this.keyPath, 'utf8'));
        data.backupPublicKey = this.identity.backupPublicKey;
        data.backupAlgorithm = 'SLH-DSA-SHA2-192f';
        data.backupSecretKeyEnc = backupSecretKeyEnc;
        writeFileSync(this.keyPath, JSON.stringify(data, null, 2));
        this._secureKeyFile();
        log.info('SLH-DSA backup keypair generated and stored');
      }
      
      // Check if identity needs regeneration (codebase changed)
      if (codebaseHash && this.identity.codebaseHash && 
          this.identity.codebaseHash !== codebaseHash) {
        log.warn('Codebase changed - regenerating node identity', {
          oldNetwork: this.identity.networkName || 'unknown',
          newNetwork: this.networkName
        });
        // Delete old identity and regenerate
        this.identity = null;
      } else {
        log.info('Loaded node identity', {
          nodeId: this.identity.nodeId,
          network: this.identity.networkName || this.networkName || 'unknown',
          algorithm: this.identity.algorithm,
          backupAlgorithm: this.identity.backupAlgorithm || 'none',
          nistLevel: this.identity.nistLevel,
          verificationPhrase: this.verificationPhrase || undefined
        });
        return this.identity;
      }
    }
    
    // Generate new identity
    if (!codebaseHash) {
      throw new Error(
        'Cannot generate node identity: codebase hash not available. ' +
        'Pass the oracle instance to init() or call setCodebaseHash() first.'
      );
    }
    
    log.info('Generating post-quantum keypair (ML-DSA-65)');
    const keyPair = generateKeyPair();
    const publicKeyBytes = hexToBytes(keyPair.publicKey);
    const nodeId = generateNodeId(publicKeyBytes, codebaseHash);

    // Generate SLH-DSA backup keypair (FIPS 205) — defense-in-depth
    // If lattice assumptions (ML-DSA) ever break, hash-based SLH-DSA still holds
    log.info('Generating SLH-DSA backup keypair (SLH-DSA-SHA2-192f)');
    const backupKeyPair = generateBackupSignatureKeyPair();
    const backupPublicKeyHex = bytesToHex(backupKeyPair.publicKey);
    const backupSecretKeyHex = bytesToHex(backupKeyPair.secretKey);

    this.identity = {
      nodeId,
      networkName: this.networkName,
      verificationPhrase: this.verificationPhrase,
      codebaseHash,  // Store for change detection
      name: nodeName,
      region,
      publicKey: keyPair.publicKey,
      secretKey: keyPair.secretKey,  // Kept in memory only
      backupPublicKey: backupPublicKeyHex,    // SLH-DSA public key (shared with peers)
      backupSecretKey: backupSecretKeyHex,    // SLH-DSA secret key (memory only)
      algorithm: keyPair.algorithm,
      backupAlgorithm: 'SLH-DSA-SHA2-192f',
      nistLevel: keyPair.nistLevel,
      createdAt: Date.now(),
      capabilities: ['listings', 'chat', 'forum', 'qcoa'],
    };

    // Encrypt secret keys for at-rest storage
    // Passphrase = pre-iO material (codebaseHash + SHA3-256(publicKey))
    // This binds the encrypted file to both the codebase AND this specific keypair
    const secretKeyEnc = this._encryptSecretKey(keyPair.secretKey, keyPair.publicKey, codebaseHash);
    const backupSecretKeyEnc = this._encryptSecretKey(backupSecretKeyHex, keyPair.publicKey, codebaseHash);
    const toStore = { ...this.identity, secretKeyEnc, backupSecretKeyEnc };
    delete toStore.secretKey;          // Never write plaintext ML-DSA secret key to disk
    delete toStore.backupSecretKey;    // Never write plaintext SLH-DSA secret key to disk
    writeFileSync(this.keyPath, JSON.stringify(toStore, null, 2));
    this._secureKeyFile();
    log.info('Generated new node identity', {
      nodeId,
      network: this.networkName,
      algorithm: 'ML-DSA-65 (FIPS 204, NIST Level 3)',
      backupAlgorithm: 'SLH-DSA-SHA2-192f (FIPS 205)',
      publicKeySize: keyPair.publicKey.length / 2,
      verificationPhrase: this.verificationPhrase || undefined
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
