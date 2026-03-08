/**
 * NAMCHE Gateway - Network Authenticated Mesh Certificate Hub & Exchange
 * 
 * Trustless certificate verification using mathematical proofs.
 * "Math as Authority - No human in the loop, no human weakness."
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * ⚠️  SECURITY: This module implements the 8-step verification flow.
 *     All trust decisions are mathematical computations - no exceptions.
 *     Defense-in-depth: NIST (Gate 2) + 144T (Gate 8) must BOTH verify.
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * The 8 Gates of Verification:
 * 1. STRUCTURE_OK       - Valid DOKO format
 * 2. SIGNATURE_OK       - ML-DSA-65 signature verifies (NIST)
 * 3. NODEID_OK          - NodeID matches two-part derivation (network + instance)
 * 4. TEMPORAL_OK        - Not expired, not from future
 * 5. NETWORK_OK         - Correct network name
 * 6. NOT_REVOKED        - Not in revocation log
 * 7. DOMAINS_OK         - Quorum verified domain claims (if applicable)
 * 8. TRIT_COMMITMENT_OK - 144T backbone verification (if present)
 * 
 * @module security/namche-gateway
 * @version 1.0.0
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_256 as _nobleSha3 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
// ACCEL: Hardware-accelerated crypto
import { sha3_256, mlDsa65Verify } from '../utils/accel.js';
import { EventEmitter } from 'events';
import { generateNodeId, getCodebaseHash, signMessage } from '../identity/node-key.js';
import { deriveNetworkName } from '../oracle/network-identity.js';
import { createLogger } from '../utils/logger.js';
// SAKSHI: Observational verification & revocation agreement
import { NodeWitness, checkMathematicalAgreement, checkRevocationAgreement } from './sakshi.js';
// 144T: Ternary backbone security (defense-in-depth with NIST)
import { TritCommitment } from './trit-commitment.js';

const log = createLogger('security:namche');

/**
 * JSON Canonicalization (RFC 8785 simplified)
 * Ensures deterministic hashing of DOKO objects
 */
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
 * DOKO (Distributed Ownership & Key Object) types
 */
export const DOKO_TYPES = {
  NODE_IDENTITY: 'node-identity',
  DOMAIN_CLAIM: 'domain-claim',
  SERVICE_BINDING: 'service-binding',
};

/**
 * Verification result codes
 */
export const VERIFY_RESULT = {
  VALID: 'MATHEMATICALLY_VERIFIED',
  MALFORMED_STRUCTURE: 'MALFORMED_STRUCTURE',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  NODEID_MISMATCH: 'NODEID_MISMATCH',
  WRONG_NETWORK_IN_NODEID: 'WRONG_NETWORK_IN_NODEID',
  ISSUED_IN_FUTURE: 'ISSUED_IN_FUTURE',
  EXPIRED: 'EXPIRED',
  WRONG_NETWORK: 'WRONG_NETWORK',
  REVOKED: 'REVOKED',
  DOMAIN_VERIFICATION_FAILED: 'DOMAIN_VERIFICATION_FAILED',
  INSUFFICIENT_QUORUM: 'INSUFFICIENT_QUORUM',
  TRIT_COMMITMENT_INVALID: 'TRIT_COMMITMENT_INVALID',
};

/**
 * Default configuration
 */
const DEFAULT_CONFIG = {
  networkName: 'yakmesh-mainnet',
  domainVerificationQuorum: 3,
  domainVerificationTimeout: 30000,
  dokoCacheSize: 10000,
  dokoCacheTTL: 86400000, // 24 hours
  maxClockSkew: 300000, // 5 minutes
};

/**
 * Simple LRU Cache for DOKOs
 */
class LRUCache {
  constructor(maxSize = 1000) {
    this.maxSize = maxSize;
    this.cache = new Map();
  }

  get(key) {
    if (!this.cache.has(key)) return undefined;
    const value = this.cache.get(key);
    // Move to end (most recently used)
    this.cache.delete(key);
    this.cache.set(key, value);
    return value;
  }

  set(key, value) {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxSize) {
      // Remove oldest (first) entry
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }

  has(key) {
    return this.cache.has(key);
  }

  delete(key) {
    return this.cache.delete(key);
  }

  clear() {
    this.cache.clear();
  }

  get size() {
    return this.cache.size;
  }
}

/**
 * Append-only Revocation Log
 */
class RevocationLog {
  constructor() {
    this.revocations = new Map(); // dokoHash -> revocation record
  }

  add(dokoHash, revocation) {
    if (!this.revocations.has(dokoHash)) {
      this.revocations.set(dokoHash, {
        ...revocation,
        recordedAt: Date.now(),
      });
      return true;
    }
    return false; // Already revoked
  }

  contains(dokoHash) {
    return this.revocations.has(dokoHash);
  }

  get(dokoHash) {
    return this.revocations.get(dokoHash);
  }

  getAll() {
    return Array.from(this.revocations.entries());
  }

  get size() {
    return this.revocations.size;
  }
}

/**
 * NamcheGateway - The 7-Gate Verification Engine
 * 
 * @example
 * const gateway = new NamcheGateway({ networkName: 'yakmesh-mainnet' });
 * const result = await gateway.verify(doko);
 * if (result.valid) {
 *   console.log('DOKO verified:', result.checks);
 * } else {
 *   console.log('Verification failed:', result.reason);
 * }
 */
export class NamcheGateway extends EventEmitter {
  constructor(options = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...options };
    this.networkName = this.config.networkName;
    this.dokoCache = new LRUCache(this.config.dokoCacheSize);
    this.revocationLog = new RevocationLog();
    this.verifiedDomains = new Map(); // domain -> doko that verified it
    this.revocationReports = new Map(); // dokoHash -> Array of { witness, evidence }

    this.stats = {
      verificationsAttempted: 0,
      verificationsSucceeded: 0,
      verificationsFailed: 0,
      revocationsProcessed: 0,
    };
  }

  /**
   * Get the current network name derived from codebase hash
   * @returns {string} Network name (e.g., "qubit-lattice-prism")
   */
  getNetworkName() {
    const codebaseHash = getCodebaseHash();
    if (codebaseHash) {
      return deriveNetworkName(codebaseHash, 3);
    }
    return this.networkName;
  }

  /**
   * Compute DOKO hash for unique identification
   * @param {Object} doko - The DOKO object
   * @returns {string} SHA3-256 hash (hex)
   */
  computeDokoHash(doko) {
    const payload = this.getDokoPayload(doko);
    const hash = sha3_256(utf8ToBytes(payload));
    return bytesToHex(hash);
  }

  /**
   * Get DOKO payload for signing/hashing (excludes signature)
   * @param {Object} doko - The DOKO object
   * @returns {string} Canonicalized JSON without signature
   */
  getDokoPayload(doko) {
    const { signature, ...rest } = doko;
    return canonicalize(rest);
  }

  /**
   * ═══════════════════════════════════════════════════════════════════════════
   * THE 7-GATE VERIFICATION FLOW
   * ═══════════════════════════════════════════════════════════════════════════
   * 
   * @param {Object} doko - The DOKO to verify
   * @returns {Object} Verification result { valid, reason, checks?, detail? }
   */
  async verify(doko) {
    this.stats.verificationsAttempted++;
    const checks = [];

    try {
      // ─────────────────────────────────────────────────────────────────────
      // GATE 1: STRUCTURAL VALIDITY
      // ─────────────────────────────────────────────────────────────────────
      const structureResult = this.checkStructure(doko);
      if (!structureResult.valid) {
        return this.fail(VERIFY_RESULT.MALFORMED_STRUCTURE, structureResult.detail);
      }
      checks.push('STRUCTURE_OK');

      // ─────────────────────────────────────────────────────────────────────
      // GATE 2: SIGNATURE VALIDITY (Math!)
      // ─────────────────────────────────────────────────────────────────────
      const sigResult = await this.checkSignature(doko);
      if (!sigResult.valid) {
        return this.fail(VERIFY_RESULT.INVALID_SIGNATURE, sigResult.detail);
      }
      checks.push('SIGNATURE_OK');

      // ─────────────────────────────────────────────────────────────────────
      // GATE 3: NODEID DERIVATION (Math + iO!)
      // ─────────────────────────────────────────────────────────────────────
      const nodeIdResult = this.checkNodeId(doko);
      if (!nodeIdResult.valid) {
        return this.fail(nodeIdResult.reason, nodeIdResult.detail);
      }
      checks.push('NODEID_OK');

      // ─────────────────────────────────────────────────────────────────────
      // GATE 4: TEMPORAL VALIDITY (Math!)
      // ─────────────────────────────────────────────────────────────────────
      const temporalResult = this.checkTemporal(doko);
      if (!temporalResult.valid) {
        return this.fail(temporalResult.reason, temporalResult.detail);
      }
      checks.push('TEMPORAL_OK');

      // ─────────────────────────────────────────────────────────────────────
      // GATE 5: NETWORK MATCH
      // ─────────────────────────────────────────────────────────────────────
      const networkResult = this.checkNetwork(doko);
      if (!networkResult.valid) {
        return this.fail(VERIFY_RESULT.WRONG_NETWORK, networkResult.detail);
      }
      checks.push('NETWORK_OK');

      // ─────────────────────────────────────────────────────────────────────
      // GATE 6: REVOCATION STATUS
      // ─────────────────────────────────────────────────────────────────────
      const dokoHash = this.computeDokoHash(doko);
      const revocationResult = this.checkRevocation(dokoHash);
      if (!revocationResult.valid) {
        return this.fail(VERIFY_RESULT.REVOKED, revocationResult.detail);
      }
      checks.push('NOT_REVOKED');

      // ─────────────────────────────────────────────────────────────────────
      // GATE 7: DOMAIN PROOFS (if applicable)
      // ─────────────────────────────────────────────────────────────────────
      if (doko.domains && doko.domains.length > 0) {
        const domainsResult = await this.checkDomains(doko);
        if (!domainsResult.valid) {
          return this.fail(
            VERIFY_RESULT.DOMAIN_VERIFICATION_FAILED,
            domainsResult.detail,
            { domain: domainsResult.domain }
          );
        }
        checks.push('DOMAINS_OK');
      }

      // ─────────────────────────────────────────────────────────────────────
      // GATE 8: 144T COMMITMENT (if present — defense-in-depth)
      // ─────────────────────────────────────────────────────────────────────
      // The 144T commitment provides a second cryptographic layer independent
      // of NIST. Both ML-DSA-65 (Gate 2) AND 144T must verify for full trust.
      // This means an attacker must break BOTH NIST and lattice-hard SIS.
      if (doko.tritCommitment) {
        const tritResult = this.checkTritCommitment(doko);
        if (!tritResult.valid) {
          return this.fail(
            VERIFY_RESULT.TRIT_COMMITMENT_INVALID,
            tritResult.detail,
            { tritChecks: tritResult.checks }
          );
        }
        checks.push('TRIT_COMMITMENT_OK');
      }

      // ═══════════════════════════════════════════════════════════════════════
      // ALL 8 GATES PASSED - MATHEMATICALLY VERIFIED (DUAL-LAYER)
      // ═══════════════════════════════════════════════════════════════════════
      this.stats.verificationsSucceeded++;

      // Cache the verified DOKO
      this.dokoCache.set(dokoHash, {
        doko,
        verifiedAt: Date.now(),
        checks,
      });

      this.emit('verified', { doko, dokoHash, checks });

      return {
        valid: true,
        reason: VERIFY_RESULT.VALID,
        checks,
        dokoHash,
      };

    } catch (error) {
      this.stats.verificationsFailed++;
      return this.fail('VERIFICATION_ERROR', error.message);
    }
  }

  /**
   * Create a failure result
   */
  fail(reason, detail, extra = {}) {
    this.stats.verificationsFailed++;
    this.emit('verification-failed', { reason, detail, ...extra });
    return {
      valid: false,
      reason,
      detail,
      ...extra,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // GATE IMPLEMENTATIONS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * GATE 1: Check DOKO structure
   */
  checkStructure(doko) {
    const required = ['version', 'type', 'nodeId', 'publicKey', 'issuedAt', 'expiresAt', 'signature'];

    for (const field of required) {
      if (!(field in doko)) {
        return { valid: false, detail: `Missing required field: ${field}` };
      }
    }

    if (!Object.values(DOKO_TYPES).includes(doko.type)) {
      return { valid: false, detail: `Invalid DOKO type: ${doko.type}` };
    }

    if (typeof doko.issuedAt !== 'number' || typeof doko.expiresAt !== 'number') {
      return { valid: false, detail: 'Timestamps must be numbers' };
    }

    if (doko.expiresAt <= doko.issuedAt) {
      return { valid: false, detail: 'expiresAt must be after issuedAt' };
    }

    return { valid: true };
  }

  /**
   * GATE 2: Check ML-DSA-65 signature
   */
  async checkSignature(doko) {
    try {
      const payload = this.getDokoPayload(doko);
      const payloadBytes = utf8ToBytes(payload);
      const publicKey = hexToBytes(doko.publicKey);
      const signature = hexToBytes(doko.signature);

      const valid = mlDsa65Verify(signature, payloadBytes, publicKey);

      if (!valid) {
        return { valid: false, detail: 'ML-DSA-65 signature verification failed' };
      }

      return { valid: true };
    } catch (error) {
      return { valid: false, detail: `Signature check error: ${error.message}` };
    }
  }

  /**
   * GATE 3: Check NodeID derivation
   * 
   * ⚠️ SECURITY: NodeID MUST be the two-part composite:
   *    node-[networkName]-[instanceId]
   *    
   *    DO NOT simplify to SHA3-256(publicKey)!
   *    See identity/node-key.js for security rationale.
   */
  checkNodeId(doko) {
    try {
      // The nodeId must follow the format: node-[networkName]-[instanceId]
      if (!doko.nodeId.startsWith('node-')) {
        return {
          valid: false,
          reason: VERIFY_RESULT.NODEID_MISMATCH,
          detail: 'NodeID must start with "node-"'
        };
      }

      // Extract the network name from the nodeId
      const parts = doko.nodeId.split('-');
      if (parts.length < 3) {
        return {
          valid: false,
          reason: VERIFY_RESULT.NODEID_MISMATCH,
          detail: 'NodeID must have format node-[networkName]-[instanceId]'
        };
      }

      // Verify the network portion matches our expected network
      const ourNetworkName = this.getNetworkName();

      // The network name could be multiple words (e.g., "qubit-lattice-prism")
      // We need to check if the nodeId contains our network name after "node-"
      const nodeIdWithoutPrefix = doko.nodeId.substring(5); // Remove "node-"

      if (!nodeIdWithoutPrefix.startsWith(ourNetworkName + '-')) {
        return {
          valid: false,
          reason: VERIFY_RESULT.WRONG_NETWORK_IN_NODEID,
          detail: `NodeID network mismatch. Expected: ${ourNetworkName}, Got: ${nodeIdWithoutPrefix.split('-').slice(0, -1).join('-')}`
        };
      }

      // ════════════════════════════════════════════════════════════════════
      // CRITICAL: Verify instanceId is correctly derived from public key
      // This prevents identity spoofing where attacker uses their key
      // but claims someone else's nodeId
      // ════════════════════════════════════════════════════════════════════
      const codebaseHash = getCodebaseHash();
      if (codebaseHash) {
        // Full verification: regenerate the expected nodeId from the publicKey
        const publicKeyBytes = hexToBytes(doko.publicKey);
        const expectedNodeId = generateNodeId(publicKeyBytes, codebaseHash);

        if (doko.nodeId !== expectedNodeId) {
          return {
            valid: false,
            reason: VERIFY_RESULT.NODEID_MISMATCH,
            detail: `NodeID does not match public key derivation. Expected: ${expectedNodeId}, Got: ${doko.nodeId}`
          };
        }
      }
      // If no codebase hash, we can only verify structure (cross-network scenario)
      // This is a known limitation documented in SECURITY.md

      return { valid: true };
    } catch (error) {
      return {
        valid: false,
        reason: VERIFY_RESULT.NODEID_MISMATCH,
        detail: `NodeID check error: ${error.message}`
      };
    }
  }

  /**
   * GATE 4: Check temporal validity
   */
  checkTemporal(doko) {
    const now = Date.now();
    const maxSkew = this.config.maxClockSkew;

    // Check not issued in the future (with clock skew allowance)
    if (doko.issuedAt > now + maxSkew) {
      return {
        valid: false,
        reason: VERIFY_RESULT.ISSUED_IN_FUTURE,
        detail: `DOKO issued in future: ${new Date(doko.issuedAt).toISOString()}`
      };
    }

    // Check not expired
    if (doko.expiresAt < now) {
      return {
        valid: false,
        reason: VERIFY_RESULT.EXPIRED,
        detail: `DOKO expired at: ${new Date(doko.expiresAt).toISOString()}`
      };
    }

    return { valid: true };
  }

  /**
   * GATE 5: Check network match
   */
  checkNetwork(doko) {
    if (doko.networkName && doko.networkName !== this.networkName) {
      return {
        valid: false,
        detail: `Network mismatch. Expected: ${this.networkName}, Got: ${doko.networkName}`
      };
    }
    return { valid: true };
  }

  /**
   * GATE 6: Check revocation status
   */
  checkRevocation(dokoHash) {
    if (this.revocationLog.contains(dokoHash)) {
      const revocation = this.revocationLog.get(dokoHash);
      return {
        valid: false,
        detail: `DOKO revoked at ${new Date(revocation.revokedAt).toISOString()}, reason: ${revocation.reason}`
      };
    }
    return { valid: true };
  }

  /**
   * GATE 7: Check domain proofs
   */
  async checkDomains(doko) {
    const quorum = this.config.domainVerificationQuorum;

    for (const domain of doko.domains) {
      const validProofs = await this.verifyDomainProofs(domain);

      if (validProofs < quorum) {
        return {
          valid: false,
          domain: domain.name,
          detail: `Insufficient quorum for ${domain.name}: have ${validProofs}, need ${quorum}`
        };
      }
    }

    return { valid: true };
  }

  /**
   * GATE 8: Check 144T commitment (backbone verification)
   * 
   * This gate provides DEFENSE-IN-DEPTH alongside NIST (Gate 2).
   * The 144T commitment uses YPC-27 (lattice-hard SIS problem) and
   * polynomial binding to ensure the payload is tied to the sender's
   * 144T mesh address.
   * 
   * Security properties:
   * - YPC-27 operates in ring Z[x]/(x^27-1) mod 3
   * - Forging requires solving the Shortest Vector Problem
   * - Independent of NIST — if NIST is backdoored, 144T still holds
   * - Both layers must be broken to compromise a message
   * 
   * @param {Object} doko — DOKO with tritCommitment field
   * @returns {Object} — { valid, detail?, checks? }
   */
  checkTritCommitment(doko) {
    // Get the payload (everything except signature and tritCommitment)
    const { signature, tritCommitment, ...payloadFields } = doko;

    if (!TritCommitment.isValidStructure(tritCommitment)) {
      return {
        valid: false,
        detail: 'Invalid tritCommitment structure',
        checks: [],
      };
    }

    // Verify the 144T commitment against the DOKO payload
    const result = TritCommitment.verify(payloadFields, tritCommitment);

    if (!result.valid) {
      log.warn('144T commitment verification FAILED', {
        reason: result.reason,
        detail: result.detail,
        checks: result.checks,
      });
      return {
        valid: false,
        detail: `144T: ${result.reason} — ${result.detail || 'verification failed'}`,
        checks: result.checks,
      };
    }

    log.debug('144T commitment verified (defense-in-depth active)', {
      checks: result.checks,
    });

    return { valid: true, checks: result.checks };
  }

  /**
   * Verify domain proofs from multiple verifiers
   * Uses SAKSHI observational verification — mathematical agreement, not voting
   */
  async verifyDomainProofs(domainClaim) {
    let validProofs = 0;

    if (!domainClaim.proofs || !Array.isArray(domainClaim.proofs)) {
      return 0;
    }

    // Collect SAKSHI observations from each proof verifier
    const observations = [];

    for (const proof of domainClaim.proofs) {
      try {
        // Verify the verifier's signature on the beacon hash
        const proofPayload = canonicalize({
          domain: domainClaim.name,
          beaconHash: proof.beaconHash,
          timestamp: proof.timestamp,
        });

        const payloadBytes = utf8ToBytes(proofPayload);
        const publicKey = hexToBytes(proof.verifierPublicKey);
        const signature = hexToBytes(proof.signature);

        const proofValid = mlDsa65Verify(signature, payloadBytes, publicKey);

        // SAKSHI: Record each verifier's observation
        const witness = new NodeWitness({
          nodeId: proof.verifierNodeId || bytesToHex(publicKey.slice(0, 16)),
        });
        observations.push({
          witness,
          value: proofValid ? proof.beaconHash : 'INVALID_SIGNATURE',
        });

        if (proofValid) {
          validProofs++;
        }
      } catch (error) {
        // Invalid proof format, skip
        continue;
      }
    }

    // SAKSHI: Check mathematical agreement across all proof observations
    if (observations.length > 0) {
      const agreement = checkMathematicalAgreement(observations);
      if (agreement.isAgreed) {
        log.debug('SAKSHI: Domain proofs agree mathematically', {
          domain: domainClaim.name,
          proofCount: validProofs,
          confidence: agreement.confidence,
        });
      } else if (agreement.isDisagreed) {
        log.warn('SAKSHI: Domain proof disagreement — flagging for recomputation', {
          domain: domainClaim.name,
          reason: agreement.reason,
          action: agreement.data?.action,
        });
        // Disagreement means proofs don't agree — return 0 to fail quorum
        return 0;
      }
    }

    return validProofs;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // REVOCATION MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Process a revocation request
   * @param {Object} revocation - The revocation message
   * @param {Object} originalDoko - The DOKO being revoked (for verification)
   */
  async processRevocation(revocation, originalDoko) {
    // Owner can always revoke directly (self-revocation)
    if (revocation.revokedBy === originalDoko.nodeId) {
      return this._processOwnerRevocation(revocation, originalDoko);
    }

    // Non-owner: treat as a revocation REPORT for SAKSHI consensus
    // SAKSHI uses mathematical agreement (do nodes agree on what happened?)
    // NOT tier-weighted voting (SIRDAR's revocation counts 2x)
    return this.processRevocationReport({
      reportedBy: revocation.revokedBy,
      reason: revocation.reason,
      timestamp: revocation.revokedAt,
    }, revocation.dokoHash);
  }

  /**
   * Process self-revocation from the DOKO owner
   * @private
   */
  async _processOwnerRevocation(revocation, originalDoko) {
    const revocationPayload = canonicalize({
      dokoHash: revocation.dokoHash,
      reason: revocation.reason,
      revokedAt: revocation.revokedAt,
      revokedBy: revocation.revokedBy,
    });

    try {
      const payloadBytes = utf8ToBytes(revocationPayload);
      const publicKey = hexToBytes(originalDoko.publicKey);
      const signature = hexToBytes(revocation.signature);

      const valid = mlDsa65Verify(signature, payloadBytes, publicKey);

      if (!valid) {
        return { success: false, reason: 'Invalid revocation signature' };
      }

      // Add to revocation log
      this.revocationLog.add(revocation.dokoHash, revocation);
      this.stats.revocationsProcessed++;

      // Remove from cache if present
      this.dokoCache.delete(revocation.dokoHash);

      this.emit('revoked', { dokoHash: revocation.dokoHash, revocation });

      return { success: true };
    } catch (error) {
      return { success: false, reason: `Revocation processing error: ${error.message}` };
    }
  }

  /**
   * Process a revocation report from the mesh (SAKSHI consensus)
   * 
   * Multiple nodes can report evidence of compromise/malice.
   * Revocation happens when reports mathematically agree — not by weighted vote.
   * 
   * @param {Object} report - The revocation report
   * @param {string} report.reportedBy - NodeId of the reporting node
   * @param {string} report.reason - Reason for revocation
   * @param {number} [report.timestamp] - When the issue was observed
   * @param {string} targetDokoHash - Hash of the DOKO to potentially revoke
   * @returns {Object} Result: { success, method?, reason?, state? }
   */
  processRevocationReport(report, targetDokoHash) {
    if (!this.revocationReports.has(targetDokoHash)) {
      this.revocationReports.set(targetDokoHash, []);
    }

    const reports = this.revocationReports.get(targetDokoHash);
    const witness = new NodeWitness({ nodeId: report.reportedBy });

    reports.push({
      witness,
      evidence: {
        reason: report.reason,
        targetId: targetDokoHash,
        timestamp: report.timestamp || Date.now(),
      },
    });

    // SAKSHI: Check mathematical agreement across all revocation reports
    const minReports = this.config.minRevocationReports || 3;
    const result = checkRevocationAgreement(reports, { minReports });

    if (result.isAgreed) {
      // Mesh agrees on revocation — execute it
      const revocationRecord = {
        dokoHash: targetDokoHash,
        reason: result.data.evidence?.reason || report.reason,
        revokedAt: result.data.timestamp || Date.now(),
        revokedBy: 'MESH_CONSENSUS',
        reportCount: result.data.reportCount,
        method: 'SAKSHI_AGREEMENT',
      };

      this.revocationLog.add(targetDokoHash, revocationRecord);
      this.dokoCache.delete(targetDokoHash);
      this.revocationReports.delete(targetDokoHash);
      this.stats.revocationsProcessed++;

      log.info('SAKSHI: Mesh revocation consensus reached', {
        dokoHash: targetDokoHash,
        reportCount: result.data.reportCount,
      });

      this.emit('revoked', {
        dokoHash: targetDokoHash,
        revocation: revocationRecord,
        method: 'SAKSHI_AGREEMENT',
      });

      return { success: true, method: 'SAKSHI_AGREEMENT' };
    }

    if (result.isDisagreed) {
      log.debug('SAKSHI: Revocation reports disagree', {
        dokoHash: targetDokoHash,
        reason: result.reason,
      });
      return { success: false, reason: 'Reports disagree on evidence', details: result.reason };
    }

    // PENDING — need more reports
    log.debug('SAKSHI: Revocation report recorded, awaiting consensus', {
      dokoHash: targetDokoHash,
      currentReports: reports.length,
      minRequired: minReports,
    });
    return { success: false, reason: 'Pending — need more reports', state: 'PENDING' };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CACHE & LOOKUP
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Lookup a verified DOKO by hash
   */
  lookupByHash(dokoHash) {
    const cached = this.dokoCache.get(dokoHash);
    if (cached) {
      // Check TTL
      if (Date.now() - cached.verifiedAt < this.config.dokoCacheTTL) {
        return cached.doko;
      }
      // Expired, remove from cache
      this.dokoCache.delete(dokoHash);
    }
    return null;
  }

  /**
   * Lookup a verified DOKO by nodeId
   */
  lookupByNodeId(nodeId) {
    for (const [hash, cached] of this.dokoCache.cache.entries()) {
      if (cached.doko.nodeId === nodeId) {
        if (Date.now() - cached.verifiedAt < this.config.dokoCacheTTL) {
          return cached.doko;
        }
      }
    }
    return null;
  }

  /**
   * Lookup a verified DOKO by domain
   * Searches through cached DOKOs for one with a matching verified domain claim
   * @param {string} domain - The domain to search for
   * @returns {Object|null} The DOKO if found and still valid
   */
  lookupByDomain(domain) {
    const normalizedDomain = domain.toLowerCase().replace(/^www\./, '');

    for (const [hash, cached] of this.dokoCache.cache.entries()) {
      // Check TTL first
      if (Date.now() - cached.verifiedAt >= this.config.dokoCacheTTL) {
        continue;
      }

      // Check if DOKO has domain claims
      const doko = cached.doko;
      if (doko.claims?.domains) {
        for (const domainClaim of doko.claims.domains) {
          const claimDomain = domainClaim.domain?.toLowerCase().replace(/^www\./, '');
          if (claimDomain === normalizedDomain && domainClaim.verified) {
            return doko;
          }
        }
      }
    }
    return null;
  }

  /**
   * Get gateway statistics
   */
  getStats() {
    return {
      ...this.stats,
      cacheSize: this.dokoCache.size,
      revocationsCount: this.revocationLog.size,
    };
  }

  /**
   * Create a DOKO with 144T commitment (dual-layer security).
   * 
   * This is the recommended way to create DOKOs for full defense-in-depth:
   * - NIST layer: ML-DSA-65 signature
   * - 144T layer: YPC-27 + polynomial binding commitment
   * 
   * @param {Object} dokoFields — DOKO fields (type, nodeId, publicKey, etc.)
   * @param {string} secretKey — Sender's ML-DSA-65 secret key (hex)
   * @param {TritAddress} senderAddress — Sender's 144T mesh address
   * @returns {Object} — Complete DOKO with signature and tritCommitment
   */
  static createDokoWithCommitment(dokoFields, secretKey, senderAddress) {
    // Canonicalize for deterministic signing
    const payload = canonicalize(dokoFields);

    // Layer 1: NIST signature (ML-DSA-65)
    const signature = signMessage(payload, secretKey);

    // Layer 2: 144T commitment (YPC-27 + polynomial binding)
    const tritCommitment = TritCommitment.create(dokoFields, senderAddress);

    return {
      ...dokoFields,
      signature,
      tritCommitment,
    };
  }
}

export default NamcheGateway;
