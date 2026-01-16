/**
 * Lantern Node Identity - Post-Quantum Secure
 * Uses ML-DSA-65 (Dilithium3) from FIPS 204
 * 
 * Security Level: NIST Level 3 (~192-bit classical security)
 * Quantum Resistant: Yes (lattice-based)
 * 
 * IMPORTANT: Node IDs use iO (indistinguishability obfuscation) style
 * derivation to avoid exposing raw hashes. The internal hash is kept
 * private while the public-facing ID is a human-readable derived name.
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';

// Import iO network identity for obfuscated node IDs
import { deriveNetworkName, deriveNetworkId } from '../oracle/network-identity.js';

/**
 * Generate a unique node ID from public key using iO obfuscation
 * Instead of exposing raw hashes, we derive a human-readable name
 * 
 * @param {Uint8Array} publicKey - The node's public key
 * @returns {string} iO-derived node ID like "qubit-lattice-prism"
 */
export function generateNodeId(publicKey) {
  const hash = sha3_256(publicKey);
  const hashHex = bytesToHex(hash);
  
  // Use iO to derive a human-readable, non-reversible ID
  // The raw hash is never exposed externally
  const networkName = deriveNetworkName(hashHex, 3);
  const shortId = deriveNetworkId(hashHex);
  
  // Format: "node-[3-word-name]-[short-id]"
  // e.g., "node-qubit-lattice-prism-pq-a7x9"
  return `node-${networkName}-${shortId}`;
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
 */
export class NodeIdentity {
  constructor(dataDir = './data') {
    this.dataDir = dataDir;
    this.keyPath = join(dataDir, 'node-key.json');
    this.identity = null;
  }

  /**
   * Initialize or load node identity
   */
  async init(nodeName = 'Lantern Node', region = 'local') {
    // Ensure data directory exists
    if (!existsSync(this.dataDir)) {
      mkdirSync(this.dataDir, { recursive: true });
    }

    // Load existing identity or generate new one
    if (existsSync(this.keyPath)) {
      const data = JSON.parse(readFileSync(this.keyPath, 'utf8'));
      this.identity = data;
      console.log(`✓ Loaded node identity: ${this.identity.nodeId}`);
      console.log(`  Algorithm: ${this.identity.algorithm} (NIST Level ${this.identity.nistLevel})`);
    } else {
      console.log('⚙ Generating post-quantum keypair (ML-DSA-65)...');
      const keyPair = generateKeyPair();
      const publicKeyBytes = hexToBytes(keyPair.publicKey);
      const nodeId = generateNodeId(publicKeyBytes);

      this.identity = {
        nodeId,
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
      console.log(`  Algorithm: ML-DSA-65 (FIPS 204, NIST Level 3)`);
      console.log(`  Public Key Size: ${keyPair.publicKey.length / 2} bytes`);
    }

    return this.identity;
  }

  /**
   * Get public identity (safe to share with other nodes)
   */
  getPublicIdentity() {
    if (!this.identity) throw new Error('Identity not initialized');
    
    return {
      nodeId: this.identity.nodeId,
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
