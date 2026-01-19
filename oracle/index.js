/**
 * Yakmesh Distributed Oracle
 * 
 * Main entry point for the self-verifying, distributed oracle system.
 * 
 * This module provides:
 * - ValidationOracle: Self-verifying validation engine
 * - CodeProofProtocol: Peer verification protocol
 * - ConsensusEngine: Distributed consensus mechanism
 * - ModuleSealer: Cryptographic sealing system
 * - NetworkIdentity: iO obfuscation for identity derivation
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * ⚠️  iO IDENTITY OBFUSCATION - CRITICAL SECURITY PRIMITIVE  ⚠️
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * ALL user-facing and network-exposed identifiers MUST use the iO system:
 * 
 *   import { deriveNetworkName, deriveNetworkId } from './oracle/index.js';
 *   
 *   // For human-readable names
 *   const name = deriveNetworkName(hash, 3);  // "qubit-lattice-prism"
 *   
 *   // For short IDs  
 *   const id = deriveNetworkId(hash);  // "pq-a7x9"
 * 
 * NEVER expose raw hashes (e.g., "7f3a9b2c...") in:
 * - Node IDs, DOKO IDs, network names
 * - API responses, logs visible to users
 * - WebSocket messages, gossip protocol
 * 
 * See oracle/network-identity.js and SECURITY.md for details.
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Philosophy:
 * "Code is the oracle. Every node running the same provably-correct code
 *  will independently arrive at the same truth. Mathematical inevitability
 *  replaces social trust."
 * 
 * @module YakmeshOracle
 * @version 1.1.0
 */

export { 
  ValidationOracle, 
  ValidationResult,
  getOracle,
  contentHash,
  deterministicStringify,
} from './validation-oracle-hardened.js';

export { 
  CodeProofProtocol, 
  ProofState,
  mutualVerification,
} from './code-proof-protocol.js';

export { 
  ConsensusEngine, 
  ContentState,
} from './consensus-engine.js';

export { 
  ModuleSealer, 
  SealedModule,
} from './module-sealer.js';

export {
  GenesisNetwork,
  createGenesisNetwork,
} from './genesis-network.js';

// v2: iO-inspired hash obfuscation
export {
  GenesisNetworkV2,
  createGenesisNetworkV2,
} from './genesis-network-v2.js';

export {
  NetworkIdentity,
  createNetworkIdentity,
  deriveNetworkName,
  deriveNetworkId,
  deriveVerificationPhrase,
  QUANTUM_WORDLIST,
} from './network-identity.js';

// Codebase lock - prevents source modification during runtime
export {
  CodebaseLock,
  getCodebaseLock,
  lockCodebase,
  unlockCodebase,
  setupUnlockOnExit,
} from './codebase-lock.js';

/**
 * Create a fully configured oracle system for a Lantern node
 * 
 * @param {Object} nodeIdentity - The node's identity
 * @param {Object} options - Configuration options
 * @returns {Object} Configured oracle system
 */
export function createOracleSystem(nodeIdentity, options = {}) {
  const { getOracle } = require('./validation-oracle-hardened.js');
  const { CodeProofProtocol } = require('./code-proof-protocol.js');
  const { ConsensusEngine } = require('./consensus-engine.js');
  
  const oracle = getOracle();
  const codeProof = new CodeProofProtocol(nodeIdentity);
  const consensus = new ConsensusEngine(nodeIdentity, options);
  
  return {
    oracle,
    codeProof,
    consensus,
    
    // Convenience methods
    validate: (type, content) => {
      switch (type) {
        case 'listing': return oracle.validateListing(content);
        case 'user': return oracle.validateUser(content);
        case 'qcoa': return oracle.validateQCoA(content);
        default: return { valid: false, reason: 'UNKNOWN_TYPE' };
      }
    },
    
    submit: (type, content, metadata) => {
      return consensus.submitContent(type, content, metadata);
    },
    
    generateChallenge: (peerId) => {
      return codeProof.generateChallenge(peerId);
    },
    
    verifyPeer: (proof) => {
      return oracle.verifyCodeProof(proof);
    },
    
    getStats: () => ({
      oracle: oracle.getModuleSeal(),
      consensus: consensus.getStats(),
      codeProof: codeProof.getStats(),
    }),
  };
}

// Version information
export const VERSION = '1.0.0';
export const ORACLE_NAME = 'Yakmesh Distributed Oracle';





