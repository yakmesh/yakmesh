/**
 * Yakmesh Machine Seed — Deterministic Identity Anchor
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * TWO-LAYER IDENTITY ARCHITECTURE
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Layer 1 — NETWORK IDENTITY (shared, code-derived):
 *   oracleHash → networkName, networkId, verificationPhrase
 *   Every node with byte-identical code arrives at the same network.
 *   Machine data is EXCLUDED entirely. This is the peering contract.
 * 
 * Layer 2 — NODE IDENTITY (unique, seed-derived):
 *   machineSeed + oracleHash + verPhrase → HKDF → ml_dsa65.keygen()
 *   The seed creates uniqueness WITHIN the network, not a separate network.
 *   If the codebase changes, the same seed produces a DIFFERENT keypair
 *   on the new network — the verification phrase acts as domain separator.
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * SEED STORAGE — HARDWARE-BOUND + YPC-27 INTEGRITY
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * The seed is NOT stored in plaintext. It is encrypted under a key derived
 * from machine-specific hardware markers (hostname, platform, dataDir).
 * An attacker who copies the seed file to another machine cannot decrypt it.
 * 
 * Additionally, a YPC-27 polynomial checksum seals the seed. SIS-hardness
 * (Short Integer Solution in Z[x]/(x^27-1) mod 3) makes it computationally
 * infeasible to craft a different seed that produces the same checksum.
 * This detects both accidental corruption AND deliberate seed injection.
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * MIGRATION CHAIN — REPUTATION CONTINUITY
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * When the codebase updates, the same seed produces a new keypair (because
 * the oracle hash changed). The migration chain records each (oracleHash,
 * publicKey) pair so reputation can be cryptographically transferred:
 * 
 *   migrationProof = sign(oldKey, "MIGRATE:" + newPubKey) +
 *                    sign(newKey, "MIGRATE:" + oldPubKey)
 * 
 * Both signatures together prove the same physical entity controls both
 * identities without revealing the seed.
 * 
 * @module identity/machine-seed
 * @version 1.0.0
 */

import { createLogger } from '../utils/logger.js';

const log = createLogger('identity:machine-seed');

import { sha3_256 } from '../utils/accel.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from 'fs';
import { join } from 'path';
import { createCipheriv, createDecipheriv, scryptSync, randomBytes } from 'crypto';
import { hostname, platform, cpus } from 'os';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha3_256 as _sha3 } from '@noble/hashes/sha3.js';

// YPC-27 polynomial integrity
import { YPC27Checksum, Poly27, bytesToTrits, DEFAULT_SEED as YPC27_DEFAULT_SEED } from '../oracle/ypc27.js';

// SST family analysis
import { bytesToFamilyTrits, analyzeBytesFamilies } from '../oracle/sst.js';

// iO derivation for domain separation
import { deriveVerificationPhrase } from '../oracle/network-identity.js';

// 144T ternary addressing for persistent machine identity
import { TritAddress, TOTAL_TRITS } from '../oracle/ternary-144t.js';


// =============================================================================
// CONSTANTS
// =============================================================================

/** Seed size in bytes */
const SEED_BYTES = 32;

/** Seed file name */
const SEED_FILENAME = 'machine-seed.json';

/** Current seed file schema version — bumped for persistentId144T */
const SCHEMA_VERSION = 2;

/** Persistent ID prefix */
const PERSISTENT_ID_PREFIX = 'yak';


// =============================================================================
// HARDWARE FINGERPRINT
// =============================================================================

/**
 * Derive a machine-specific fingerprint from hardware markers.
 * This is used to encrypt the seed at rest — the encrypted seed
 * is useless on any other machine.
 * 
 * Uses: hostname, platform, CPU model, dataDir
 * NOT in oracle hash (these are local-only values).
 * 
 * @param {string} dataDir - The node's data directory path
 * @returns {Buffer} 32-byte hardware-derived key
 */
function deriveHardwareKey(dataDir) {
  const cpuModel = cpus()[0]?.model || 'unknown-cpu';
  const fingerprint = `yakmesh:machine-seed:${hostname()}:${platform()}:${cpuModel}:${dataDir}`;
  const salt = sha3_256(new TextEncoder().encode('yakmesh-hardware-salt-2026'));
  // scrypt: N=2^14, r=8, p=1, 32-byte key
  return scryptSync(fingerprint, Buffer.from(salt), 32, {
    N: 16384, r: 8, p: 1,
  });
}


// =============================================================================
// SEED ENCRYPTION
// =============================================================================

/**
 * Encrypt the seed for at-rest storage using hardware-derived key.
 * AES-256-GCM provides authenticated encryption.
 * 
 * @param {Uint8Array} seed - Raw 32-byte seed
 * @param {string} dataDir - For hardware key derivation
 * @returns {{ ciphertext: string, nonce: string, tag: string }}
 */
function encryptSeed(seed, dataDir) {
  const key = deriveHardwareKey(dataDir);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([
    cipher.update(Buffer.from(seed)),
    cipher.final(),
  ]);
  return {
    ciphertext: encrypted.toString('hex'),
    nonce: nonce.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
  };
}

/**
 * Decrypt the seed from at-rest storage.
 * 
 * @param {{ ciphertext: string, nonce: string, tag: string }} enc
 * @param {string} dataDir - For hardware key derivation
 * @returns {Uint8Array} Raw 32-byte seed
 */
function decryptSeed(enc, dataDir) {
  const key = deriveHardwareKey(dataDir);
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
  return new Uint8Array(decrypted);
}


// =============================================================================
// YPC-27 INTEGRITY SEAL
// =============================================================================

/**
 * Compute YPC-27 polynomial checksum of the seed.
 * SIS-hard: an attacker cannot craft a different seed with the same checksum.
 * 
 * @param {Uint8Array} seed - Raw 32-byte seed
 * @returns {string} Hex-encoded YPC-27 checksum
 */
function computeSeedChecksum(seed) {
  const hasher = new YPC27Checksum(YPC27_DEFAULT_SEED);
  hasher.update(seed);
  return hasher.digestHex();
}

/**
 * Verify YPC-27 checksum of a seed.
 * 
 * @param {Uint8Array} seed - Raw seed bytes
 * @param {string} expectedHex - Expected YPC-27 checksum hex
 * @returns {boolean}
 */
function verifySeedChecksum(seed, expectedHex) {
  const computed = computeSeedChecksum(seed);
  return computed === expectedHex;
}


// =============================================================================
// KEYPAIR DERIVATION — DETERMINISTIC FROM SEED + NETWORK
// =============================================================================

/**
 * Derive a deterministic 32-byte secret for ML-DSA-65 keygen.
 * 
 * The derivation uses HKDF-SHA3-256 with:
 *   ikm  = machineSeed (32 bytes, unique per machine)
 *   salt = oracleHash (hex string of codebase hash)
 *   info = verificationPhrase + ":node-keypair" (domain separator)
 * 
 * If the codebase changes (oracleHash changes), the derived secret changes,
 * producing a completely different keypair — even with the same seed.
 * The verification phrase provides additional binding to the network identity.
 * 
 * @param {Uint8Array} seed - Raw 32-byte machine seed
 * @param {string} oracleHash - Codebase hash from the validation oracle
 * @param {string} verPhrase - Network verification phrase (from iO)
 * @returns {Uint8Array} 32-byte deterministic secret for ml_dsa65.keygen()
 */
export function deriveNodeSecret(seed, oracleHash, verPhrase) {
  if (!seed || seed.length !== SEED_BYTES) {
    throw new Error(`Machine seed must be ${SEED_BYTES} bytes, got ${seed?.length}`);
  }
  if (!oracleHash || typeof oracleHash !== 'string') {
    throw new Error('Oracle hash (codebase hash) is required for key derivation');
  }
  if (!verPhrase || typeof verPhrase !== 'string') {
    throw new Error('Verification phrase is required for key derivation');
  }

  const salt = new TextEncoder().encode(oracleHash);
  const info = new TextEncoder().encode(`${verPhrase}:node-keypair`);

  // HKDF-SHA3-256: one-way derivation, 32-byte output
  return hkdf(_sha3, seed, salt, info, 32);
}

/**
 * Derive a deterministic 72-byte secret for SLH-DSA backup keygen.
 * Uses a different info domain separator than the primary key.
 * SLH-DSA-SHA2-192f requires a 72-byte seed (FIPS 205).
 * 
 * @param {Uint8Array} seed - Raw 32-byte machine seed
 * @param {string} oracleHash - Codebase hash
 * @param {string} verPhrase - Network verification phrase
 * @returns {Uint8Array} 72-byte deterministic secret for SLH-DSA keygen
 */
export function deriveBackupSecret(seed, oracleHash, verPhrase) {
  if (!seed || seed.length !== SEED_BYTES) {
    throw new Error(`Machine seed must be ${SEED_BYTES} bytes`);
  }
  const salt = new TextEncoder().encode(oracleHash);
  const info = new TextEncoder().encode(`${verPhrase}:backup-keypair-slh-dsa`);
  return hkdf(_sha3, seed, salt, info, 72);
}


// =============================================================================
// MIGRATION CHAIN
// =============================================================================

/**
 * Compute persistent machine ID in 144T ternary format.
 * This ID is CONSTANT across all code upgrades — derived directly from seed.
 * 
 * Format: "yak-[tier1-144T]" where tier1 is 36 trits (≈57 bits entropy)
 * Example: "yak-TT00TTT00:TTT00TTT0:0TTT00TTT:00TTT00TT"
 * 
 * @param {Uint8Array} seed - Raw 32-byte machine seed
 * @returns {string} Persistent 144T identifier
 */
function computePersistentId144T(seed) {
  // Domain-separate from other derivations — "persistent-machine-id" context
  const context = new TextEncoder().encode('yakmesh:persistent-machine-id:v1');
  const combined = new Uint8Array(seed.length + context.length);
  combined.set(seed);
  combined.set(context, seed.length);

  const hash = sha3_256(combined);
  const hex = bytesToHex(hash);

  // Convert to 144T, extract tier 1 for compact persistent ID
  const tritAddr = TritAddress.fromHex(hex);
  const tier1 = tritAddr.toString().split('.')[0];

  return `${PERSISTENT_ID_PREFIX}-${tier1}`;
}

/**
 * Add a migration entry to the chain.
 * Records that this seed derived a specific publicKey under a specific oracleHash.
 * 
 * @param {Object[]} chain - Existing migration chain entries
 * @param {string} oracleHash - Current oracle hash
 * @param {string} pubKeyHash - SHA3-256 hash of the public key (not the full key!)
 * @param {string} networkName - Human-readable network name
 * @returns {Object[]} Updated chain
 */
function addMigrationEntry(chain, oracleHash, pubKeyHash, networkName) {
  const entry = {
    oracleHash: oracleHash.slice(0, 24), // First 24 chars, enough for lookup
    pubKeyHash: pubKeyHash.slice(0, 32),  // First 32 chars
    networkName,
    timestamp: new Date().toISOString(),
  };

  // Don't duplicate — if the same oracleHash already exists, skip
  const existing = chain.find(e => e.oracleHash === entry.oracleHash);
  if (existing) return chain;

  return [...chain, entry];
}


// =============================================================================
// SST ANALYSIS (INFORMATIONAL)
// =============================================================================

/**
 * Compute SST family analysis of the seed.
 * Purely informational — stored for display and future trust integration.
 * 
 * @param {Uint8Array} seed - Raw seed bytes
 * @returns {{ a: number, b: number, c: number }} Family proportions
 */
function analyzeSeedFamilies(seed) {
  return analyzeBytesFamilies(seed);
}


// =============================================================================
// MACHINE SEED MANAGER
// =============================================================================

/**
 * MachineSeed — Manages the persistent machine seed and its integrity.
 * 
 * The seed is the long-term identity anchor. Keypairs are ephemeral
 * projections of the seed onto a specific network version.
 * 
 * File stored: machine-seed.json in dataDir
 * Contents: { encryptedSeed, ypc27Checksum, persistentId144T, migrationChain[], sstFamilies, schemaVersion }
 * NEVER stored: raw seed, private keys
 * 
 * The persistentId144T is constant across ALL code upgrades — it identifies
 * the physical machine/node owner regardless of which network version is running.
 */
export class MachineSeed {
  /**
   * @param {string} dataDir - Data directory (same as NodeIdentity)
   */
  constructor(dataDir = './data') {
    this.dataDir = dataDir;
    this.seedPath = join(dataDir, SEED_FILENAME);
    this.seed = null;          // Raw seed (in memory only)
    this.persistentId = null;  // 144T persistent identity (constant across upgrades)
    this.migrationChain = [];  // History of (oracleHash, pubKeyHash) pairs
    this.sstFamilies = null;   // SST family analysis
    this.created = false;      // True if seed was just generated (first run)
  }

  /**
   * Set restrictive file permissions on seed file (owner read/write only).
   * On Windows this is a no-op (NTFS ACLs handle access differently).
   */
  _secureFile() {
    if (platform() !== 'win32') {
      try {
        chmodSync(this.seedPath, 0o600);
      } catch (e) {
        log.warn('Could not set restrictive permissions on seed file', { error: e.message });
      }
    }
  }

  /**
   * Initialize the machine seed.
   * 
   * - If seed file exists: decrypt, verify YPC-27 checksum, load migration chain
   * - If no seed file: generate random seed, compute checksum, save encrypted
   * 
   * @returns {boolean} true if seed loaded/created successfully
   */
  async init() {
    // Ensure data directory exists
    if (!existsSync(this.dataDir)) {
      mkdirSync(this.dataDir, { recursive: true });
    }

    if (existsSync(this.seedPath)) {
      return this._loadExisting();
    } else {
      return this._generateNew();
    }
  }

  /**
   * Load and verify an existing seed file.
   * @returns {boolean}
   * @private
   */
  _loadExisting() {
    try {
      const data = JSON.parse(readFileSync(this.seedPath, 'utf8'));

      // Schema check
      if (data.schemaVersion !== SCHEMA_VERSION) {
        log.warn('Seed file schema version mismatch', {
          expected: SCHEMA_VERSION,
          got: data.schemaVersion,
        });
        // Future: add migration logic for schema upgrades
      }

      // Decrypt seed using hardware-derived key
      const seed = decryptSeed(data.encryptedSeed, this.dataDir);

      // Verify YPC-27 integrity checksum
      if (!verifySeedChecksum(seed, data.ypc27Checksum)) {
        log.error('🚨 YPC-27 SEED INTEGRITY CHECK FAILED — possible tampering!');
        log.error('Seed checksum does not match. The seed file may have been modified.');
        log.error('Refusing to use potentially compromised seed.');
        throw new Error(
          'YPC-27 seed integrity check failed. Seed file may be tampered. ' +
          'Delete machine-seed.json to generate a new identity (reputation will be lost).'
        );
      }

      this.seed = seed;
      this.persistentId = data.persistentId144T || computePersistentId144T(seed);
      this.migrationChain = data.migrationChain || [];
      this.sstFamilies = data.sstFamilies || analyzeSeedFamilies(seed);
      this.created = false;

      // Schema migration: add persistentId if missing (v1 → v2)
      if (!data.persistentId144T) {
        log.info('Migrating seed file to v2 (adding persistentId144T)');
        this._updateSeedFile();
      }

      log.info('Machine seed loaded and verified', {
        ypc27: '✓',
        persistentId: this.persistentId,
        migrationEntries: this.migrationChain.length,
        sstFamilies: this.sstFamilies,
      });

      return true;
    } catch (e) {
      if (e.message.includes('YPC-27')) throw e; // Re-throw integrity failures

      log.error('Failed to load machine seed', { error: e.message });
      throw new Error(
        `Cannot load machine seed: ${e.message}. ` +
        'Wrong machine? Seed file is encrypted to the machine that created it.'
      );
    }
  }

  /**
   * Generate a new random seed, compute integrity seal, save encrypted.
   * @returns {boolean}
   * @private
   */
  _generateNew() {
    log.info('Generating new machine seed (first run on this machine)');

    // Cryptographically random 32-byte seed
    const seed = new Uint8Array(randomBytes(SEED_BYTES));

    // Compute YPC-27 integrity checksum (SIS-hard polynomial seal)
    const ypc27Checksum = computeSeedChecksum(seed);

    // Compute persistent 144T identity (constant across all upgrades)
    const persistentId144T = computePersistentId144T(seed);

    // Compute SST family analysis
    const sstFamilies = analyzeSeedFamilies(seed);

    // Encrypt seed under hardware-derived key
    const encryptedSeed = encryptSeed(seed, this.dataDir);

    // Save seed file
    const seedFile = {
      schemaVersion: SCHEMA_VERSION,
      encryptedSeed,
      ypc27Checksum,
      persistentId144T,
      sstFamilies,
      migrationChain: [],
      createdAt: new Date().toISOString(),
    };

    writeFileSync(this.seedPath, JSON.stringify(seedFile, null, 2));
    this._secureFile();

    this.seed = seed;
    this.persistentId = persistentId144T;
    this.migrationChain = [];
    this.sstFamilies = sstFamilies;
    this.created = true;

    log.info('Machine seed generated and secured', {
      persistentId: persistentId144T,
      ypc27Checksum: ypc27Checksum.slice(0, 12) + '...',
      sstFamilies,
      encrypted: true,
      hardwareBound: true,
    });

    return true;
  }

  /**
   * Record a migration entry after deriving a keypair.
   * 
   * @param {string} oracleHash - Current oracle hash
   * @param {string} pubKeyHash - SHA3-256(publicKey) hex
   * @param {string} networkName - Human-readable network name
   */
  recordMigration(oracleHash, pubKeyHash, networkName) {
    this.migrationChain = addMigrationEntry(
      this.migrationChain, oracleHash, pubKeyHash, networkName
    );

    // Update seed file with new migration entry
    this._updateSeedFile();
  }

  /**
   * Get the previous identity on the migration chain (for migration proofs).
   * 
   * @returns {{ oracleHash: string, pubKeyHash: string, networkName: string, timestamp: string } | null}
   */
  getPreviousIdentity() {
    if (this.migrationChain.length < 2) return null;
    return this.migrationChain[this.migrationChain.length - 2];
  }

  /**
   * Get the full migration chain for reputation lookup.
   * @returns {Object[]}
   */
  getMigrationChain() {
    return [...this.migrationChain];
  }

  /**
   * Check if this seed has been used on a previous network version.
   * @param {string} oracleHash - Current oracle hash
   * @returns {boolean}
   */
  hasNetworkHistory(oracleHash) {
    const currentEntry = this.migrationChain.find(
      e => e.oracleHash === oracleHash.slice(0, 24)
    );
    return this.migrationChain.length > 0 && !currentEntry;
  }

  /**
   * Update the seed file on disk (for migration chain updates).
   * Re-encrypts the seed and updates all metadata.
   * @private
   */
  _updateSeedFile() {
    if (!this.seed) {
      log.error('Cannot update seed file: seed not loaded');
      return;
    }

    const encryptedSeed = encryptSeed(this.seed, this.dataDir);
    const ypc27Checksum = computeSeedChecksum(this.seed);
    const persistentId144T = this.persistentId || computePersistentId144T(this.seed);
    const sstFamilies = this.sstFamilies || analyzeSeedFamilies(this.seed);

    const existing = existsSync(this.seedPath)
      ? JSON.parse(readFileSync(this.seedPath, 'utf8'))
      : {};

    const seedFile = {
      schemaVersion: SCHEMA_VERSION,
      encryptedSeed,
      ypc27Checksum,
      persistentId144T,
      sstFamilies,
      migrationChain: this.migrationChain,
      createdAt: existing.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    writeFileSync(this.seedPath, JSON.stringify(seedFile, null, 2));
    this._secureFile();
  }

  /**
   * Get raw seed bytes (for key derivation — NEVER log or transmit).
   * @returns {Uint8Array}
   */
  getSeed() {
    if (!this.seed) {
      throw new Error('Machine seed not initialized. Call init() first.');
    }
    return this.seed;
  }

  /**
   * Get the persistent 144T machine identity.
   * This ID is CONSTANT across all code upgrades — it identifies the
   * physical machine/node owner regardless of network version.
   * 
   * Format: "yak-[tier1-144T]"
   * Example: "yak-TT00TTT00:TTT00TTT0:0TTT00TTT:00TTT00TT"
   * 
   * @returns {string} Persistent 144T identifier
   */
  getPersistentId() {
    if (!this.persistentId) {
      throw new Error('Machine seed not initialized. Call init() first.');
    }
    return this.persistentId;
  }

  /**
   * Check if seed was just created (first run).
   * @returns {boolean}
   */
  isFirstRun() {
    return this.created;
  }
}

export default MachineSeed;