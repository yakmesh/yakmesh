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

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';

// Import iO network identity for obfuscated node IDs
import { deriveNetworkName, deriveNetworkId } from '../oracle/network-identity.js';

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
  // ml_dsa65.sign takes (message, secretKey)
  const signature = ml_dsa65.sign(messageBytes, secretKey);
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
    // ml_dsa65.verify takes (signature, message, publicKey)
    return ml_dsa65.verify(signature, messageBytes, publicKey);
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
      
      // Check if identity needs regeneration (codebase changed)
      if (codebaseHash && this.identity.codebaseHash && 
          this.identity.codebaseHash !== codebaseHash) {
        console.log('⚠️ Codebase changed - regenerating node identity...');
        console.log(`   Old network: ${this.identity.networkName || 'unknown'}`);
        console.log(`   New network: ${this.networkName}`);
        // Delete old identity and regenerate
        this.identity = null;
      } else {
        console.log(`✓ Loaded node identity: ${this.identity.nodeId}`);
        console.log(`  Network: ${this.identity.networkName || this.networkName || 'unknown'}`);
        console.log(`  Algorithm: ${this.identity.algorithm} (NIST Level ${this.identity.nistLevel})`);
        if (this.verificationPhrase) {
          console.log(`  Verify: "${this.verificationPhrase}"`);
        }
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
    
    console.log('⚙ Generating post-quantum keypair (ML-DSA-65)...');
    const keyPair = generateKeyPair();
    const publicKeyBytes = hexToBytes(keyPair.publicKey);
    const nodeId = generateNodeId(publicKeyBytes, codebaseHash);

    this.identity = {
      nodeId,
      networkName: this.networkName,
      verificationPhrase: this.verificationPhrase,
      codebaseHash,  // Store for change detection
      name: nodeName,
      region,
      publicKey: keyPair.publicKey,
      secretKey: keyPair.secretKey,
      algorithm: keyPair.algorithm,
      nistLevel: keyPair.nistLevel,
      createdAt: Date.now(),
      capabilities: ['listings', 'chat', 'forum', 'qcoa'],
    };

    writeFileSync(this.keyPath, JSON.stringify(this.identity, null, 2));
    console.log(`✓ Generated new node identity: ${nodeId}`);
    console.log(`  Network: ${this.networkName}`);
    console.log(`  Algorithm: ML-DSA-65 (FIPS 204, NIST Level 3)`);
    console.log(`  Public Key Size: ${keyPair.publicKey.length / 2} bytes`);
    if (this.verificationPhrase) {
      console.log(`  Verify: "${this.verificationPhrase}"`);
    }

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
      algorithm: this.identity.algorithm,
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
}

export default NodeIdentity;
