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
 * Module Sealer
 * 
 * Creates cryptographic seals for validation modules.
 * A sealed module is provably authentic and tamper-evident.
 * 
 * The seal binds together:
 * - Source code hash
 * - Behavior fingerprint (test vector outputs)
 * - Function hashes
 * - Genesis timestamp
 * - Creator signatures (can have multiple attestors)
 * 
 * @module ModuleSealer
 */

import { sha3_256 as _nobleSha3, sha3_512 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
// ACCEL: Hardware-accelerated crypto
import { sha3_256, mlDsa65Sign, mlDsa65Verify } from '../utils/accel.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { contentHash, deterministicStringify } from './validation-oracle-hardened.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Sealed Module Structure
 */
export class SealedModule {
  constructor() {
    this.version = null;
    this.sourceHash = null;
    this.behaviorFingerprint = null;
    this.functionHashes = {};
    this.testVectorHashes = [];
    this.genesisTimestamp = null;
    this.sealHash = null;
    this.attestations = [];
  }
  
  /**
   * Compute the seal hash (combines all module identity components)
   */
  computeSealHash() {
    const sealInput = {
      version: this.version,
      sourceHash: this.sourceHash,
      behaviorFingerprint: this.behaviorFingerprint,
      functionHashes: this.functionHashes,
      testVectorHashes: this.testVectorHashes,
      genesisTimestamp: this.genesisTimestamp,
    };
    
    return contentHash(sealInput);
  }
  
  /**
   * Verify the seal integrity
   */
  verifySealIntegrity() {
    const computedHash = this.computeSealHash();
    return computedHash === this.sealHash;
  }
  
  /**
   * Verify an attestation
   */
  verifyAttestation(attestation) {
    try {
      const messageBytes = utf8ToBytes(this.sealHash);
      const sigBytes = hexToBytes(attestation.signature);
      const pubKeyBytes = hexToBytes(attestation.publicKey);
      
      // IMPORTANT: ml_dsa65.verify(signature, message, publicKey) - signature FIRST!
      return mlDsa65Verify(sigBytes, messageBytes, pubKeyBytes);
    } catch (e) {
      return false;
    }
  }
  
  /**
   * Serialize to JSON
   */
  toJSON() {
    return {
      version: this.version,
      sourceHash: this.sourceHash,
      behaviorFingerprint: this.behaviorFingerprint,
      functionHashes: this.functionHashes,
      testVectorHashes: this.testVectorHashes,
      genesisTimestamp: this.genesisTimestamp,
      sealHash: this.sealHash,
      attestations: this.attestations,
    };
  }
  
  /**
   * Deserialize from JSON
   */
  static fromJSON(json) {
    const module = new SealedModule();
    Object.assign(module, json);
    return module;
  }
}

/**
 * Module Sealer - Creates and verifies sealed modules
 */
export class ModuleSealer {
  constructor(privateKey = null, publicKey = null) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }
  
  /**
   * Generate a new key pair for signing
   */
  static generateKeyPair() {
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    
    const keyPair = ml_dsa65.keygen(seed);
    
    return {
      privateKey: bytesToHex(keyPair.secretKey),
      publicKey: bytesToHex(keyPair.publicKey),
    };
  }
  
  /**
   * Seal a module by computing its identity and optionally signing
   * 
   * @param {string} sourcePath - Path to the source file
   * @param {string} version - Module version
   * @param {Object} testVectors - Test vectors for behavior verification
   * @returns {SealedModule}
   */
  async sealModule(sourcePath, version, testVectors = []) {
    const module = new SealedModule();
    
    // Read source
    const source = readFileSync(sourcePath, 'utf-8');
    
    // Compute source hash
    module.version = version;
    module.sourceHash = contentHash(source);
    module.genesisTimestamp = Date.now();
    
    // Extract and hash functions
    module.functionHashes = this._extractFunctionHashes(source);
    
    // Compute test vector hashes
    module.testVectorHashes = testVectors.map(tv => contentHash(tv));
    
    // Compute behavior fingerprint
    module.behaviorFingerprint = contentHash({
      functionHashes: module.functionHashes,
      testVectorHashes: module.testVectorHashes,
    });
    
    // Compute seal hash
    module.sealHash = module.computeSealHash();
    
    // Sign if we have a private key
    if (this.privateKey && this.publicKey) {
      const attestation = this._createAttestation(module.sealHash);
      module.attestations.push(attestation);
    }
    
    return module;
  }
  
  /**
   * Add an attestation to an existing sealed module
   */
  addAttestation(sealedModule) {
    if (!this.privateKey || !this.publicKey) {
      throw new Error('Cannot attest without private key');
    }
    
    const attestation = this._createAttestation(sealedModule.sealHash);
    sealedModule.attestations.push(attestation);
    
    return attestation;
  }
  
  /**
   * Verify a sealed module
   */
  verifyModule(sealedModule, expectedSourceHash = null) {
    const results = {
      valid: true,
      checks: [],
    };
    
    // Check 1: Seal integrity
    const sealValid = sealedModule.verifySealIntegrity();
    results.checks.push({
      name: 'SEAL_INTEGRITY',
      passed: sealValid,
    });
    if (!sealValid) results.valid = false;
    
    // Check 2: Source hash (if provided)
    if (expectedSourceHash) {
      const sourceMatch = sealedModule.sourceHash === expectedSourceHash;
      results.checks.push({
        name: 'SOURCE_HASH',
        passed: sourceMatch,
        expected: expectedSourceHash,
        actual: sealedModule.sourceHash,
      });
      if (!sourceMatch) results.valid = false;
    }
    
    // Check 3: Attestations
    const validAttestations = [];
    for (const attestation of sealedModule.attestations) {
      const valid = sealedModule.verifyAttestation(attestation);
      if (valid) {
        validAttestations.push(attestation.publicKey);
      }
    }
    
    results.checks.push({
      name: 'ATTESTATIONS',
      passed: validAttestations.length > 0,
      validCount: validAttestations.length,
      totalCount: sealedModule.attestations.length,
    });
    
    return results;
  }
  
  /**
   * Create an attestation (signature over seal hash)
   */
  _createAttestation(sealHash) {
    const messageBytes = utf8ToBytes(sealHash);
    const privKeyBytes = hexToBytes(this.privateKey);
    
    // IMPORTANT: ml_dsa65.sign(message, secretKey) - message FIRST!
    const signature = mlDsa65Sign(messageBytes, privKeyBytes);
    
    return {
      publicKey: this.publicKey,
      signature: bytesToHex(signature),
      timestamp: Date.now(),
      attestorId: contentHash(this.publicKey).slice(0, 16),
    };
  }
  
  /**
   * Extract function definitions and hash them
   */
  _extractFunctionHashes(source) {
    const hashes = {};
    
    // Match function definitions (simplified regex)
    const functionPatterns = [
      /(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{/g,           // method definitions
      /(\w+)\s*=\s*(?:async\s+)?function\s*\([^)]*\)/g, // function expressions
      /(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>/g,       // arrow functions
    ];
    
    for (const pattern of functionPatterns) {
      let match;
      while ((match = pattern.exec(source)) !== null) {
        const funcName = match[1];
        if (funcName && !funcName.startsWith('_')) {
          // Find the function body (simplified - just use the match context)
          const startPos = match.index;
          const contextEnd = Math.min(startPos + 500, source.length);
          const context = source.slice(startPos, contextEnd);
          
          hashes[funcName] = contentHash(context);
        }
      }
    }
    
    return hashes;
  }
  
  /**
   * Save sealed module to file
   */
  static saveSeal(sealedModule, filePath) {
    const json = JSON.stringify(sealedModule.toJSON(), null, 2);
    writeFileSync(filePath, json);
  }
  
  /**
   * Load sealed module from file
   */
  static loadSeal(filePath) {
    const json = JSON.parse(readFileSync(filePath, 'utf-8'));
    return SealedModule.fromJSON(json);
  }
}

/**
 * Hex string to bytes (utility)
 */
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export default ModuleSealer;
