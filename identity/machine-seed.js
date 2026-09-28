/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0. If a copy of that
 * license agreement was not distributed with this file, You can
 * find a link to the license at https://yakmesh.dev/license
 *
 * This Source Code Form is "Incompatible With Secondary Licenses",
 * as defined by the YAKMESH NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
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
 * Additionally, a dual-position YPC-27² checksum seals the seed — quadratic
 * forms over F₃²⁷ evaluated at the two SST root-9 positions (11, 23), for a
 * combined 3⁵⁴ ≈ 2⁸⁵·⁶ space. Forging requires solving a multivariate
 * quadratic system keyed by SHA3-256. This detects both accidental corruption
 * AND deliberate seed injection.
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
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, realpathSync, renameSync } from 'fs';
import { join, resolve } from 'path';
import { createCipheriv, createDecipheriv, scryptSync, randomBytes } from 'crypto';
import { hostname, platform, cpus } from 'os';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha3_256 as _sha3 } from '@noble/hashes/sha3.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { contextSeal, avothHashSealed } from '../utils/dna-spiral.js';

// YPC-27 polynomial integrity
import { YPC27Checksum, YPC27Power, Poly27, bytesToTrits, DEFAULT_SEED as YPC27_DEFAULT_SEED } from '../oracle/ypc27.js';

// SST family analysis
import { bytesToFamilyTrits, analyzeBytesFamilies } from '../oracle/sst.js';

// iO derivation for domain separation + QUANTUM_WORDLIST for mnemonic backup
import { deriveVerificationPhrase, QUANTUM_WORDLIST } from '../oracle/network-identity.js';

// 162T ternary addressing for persistent machine identity
import { TritAddress, TOTAL_TRITS } from '../oracle/ternary-routing.js';


// =============================================================================
// CONSTANTS
// =============================================================================

/** Seed size in bytes */
const SEED_BYTES = 32;

/** Seed file name */
const SEED_FILENAME = 'machine-seed.json';

/** Current seed file schema version — bumped for persistentId 324T
 *  (full 512-bit sealed digest → ~256-bit post-quantum preimage) */
const SCHEMA_VERSION = 4;

/** Persistent ID prefix */
const PERSISTENT_ID_PREFIX = 'yak';
// Service identities share the seed but live in a distinct namespace — a
// 'yaks-' id must never be accepted where a machine identity is expected.
const SERVICE_ID_PREFIX = 'yaks';


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
  // Bind to the RESOLVED path — the literal string ('./data') is trivially
  // reproduced by a cloned directory at a matching relative location.
  let resolvedDir;
  try { resolvedDir = realpathSync(dataDir); } catch { resolvedDir = resolve(dataDir); }
  const fingerprint = `yakmesh:machine-seed:${hostname()}:${platform()}:${cpuModel}:${resolvedDir}`;
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
 * SST positions carrying the seed checksum — the two Fibonacci digital-root-9
 * slots of the 24-position cycle (indices 11 and 23), one per half. Both are
 * tier-3: the full 9-term quadratic (T² + cross products + self-powers) under
 * two INDEPENDENT SST parameter sets (position-separated seeds + matrices).
 * Output space: 3⁵⁴ ≈ 2⁸⁵·⁶ — the power-of-2 widening of the checksum itself.
 */
const SEED_CHECKSUM_POSITIONS = [11, 23];

/**
 * Compute the seed integrity checksum — YPC-27² (power-magnified, quadratic)
 * evaluated at two tier-3 SST positions and concatenated.
 *
 * Quadratic forgery resistance: the single-position linear YPC-27 fold can be
 * inverted algebraically from known input/output pairs; the quadratic form
 * cannot — it requires solving a multivariate quadratic system over F₃²⁷.
 * Combined space is 3⁵⁴ ≈ 2⁸⁵·⁶ (birthday ~2⁴²·⁸).
 *
 * This is checksum-grade integrity, not cryptographic-grade — AES-256-GCM
 * already authenticates the ciphertext; this layer is the ternary
 * second-factor for tamper detection. Use ML-DSA for signature-grade security.
 *
 * @param {Uint8Array} seed - Raw 32-byte seed
 * @returns {string} Hex-encoded dual-position YPC-27² checksum
 */
function computeSeedChecksum(seed) {
  return Buffer.concat(
    SEED_CHECKSUM_POSITIONS.map((position) => {
      const hasher = new YPC27Power(position);
      hasher.update(seed);
      return Buffer.from(hasher.digestBytes());
    }),
  ).toString('hex');
}

/**
 * Verify YPC-27² checksum of a seed.
 *
 * @param {Uint8Array} seed - Raw seed bytes
 * @param {string} expectedHex - Expected checksum hex
 * @returns {boolean}
 */
function verifySeedChecksum(seed, expectedHex) {
  return computeSeedChecksum(seed) === expectedHex;
}

/**
 * Legacy single-position linear YPC-27 verification.
 * Accepted ONLY at the schema boundary (schemaVersion < 4) so existing seed
 * files can migrate — never consulted for current-schema files.
 */
function verifySeedChecksumLegacy(seed, expectedHex) {
  const hasher = new YPC27Checksum(YPC27_DEFAULT_SEED);
  hasher.update(seed);
  return hasher.digestHex() === expectedHex;
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

/**
 * The persistent identity key — an ML-DSA-65 keypair derived from the
 * seed ONLY (no oracleHash, no verPhrase). It survives codebase
 * upgrades, node-key rotation, and hardware migration via mnemonic;
 * it is the cryptographic personhood behind the persistentId.
 *
 * This key never signs routine traffic — it exists to prove pid
 * bindings (pid → node_id → fp → epoch) that any peer can verify.
 *
 * @param {Uint8Array} seed - Raw 32-byte machine seed
 * @returns {Uint8Array} 32-byte deterministic secret for ml_dsa65.keygen()
 */
export function derivePersistentSecret(seed) {
  if (!seed || seed.length !== SEED_BYTES) {
    throw new Error(`Machine seed must be ${SEED_BYTES} bytes, got ${seed?.length}`);
  }
  const salt = new TextEncoder().encode('yakmesh:persistent-identity:v3');
  const info = new TextEncoder().encode('persistent-signing-key');
  return hkdf(_sha3, seed, salt, info, 32);
}

/** ML-DSA-65 keypair for the persistent identity (in-memory only). */
export function persistentKeyPair(seed) {
  return ml_dsa65.keygen(derivePersistentSecret(seed));
}


// =============================================================================
// MIGRATION CHAIN
// =============================================================================

/**
 * Full-324T ternary address of a digest — an INJECTIVE base-3
 * expansion of the whole 512-bit sealed AVOTH output (big-endian
 * integer → 324 base-3 digits, most-significant first). 3^324 ≈
 * 2^513.5 covers the digest with no aliasing — unlike the legacy
 * byte%243 → 5-trits codec, no entropy is dropped and no two
 * digests collide in the encoding.
 *
 * Security: ~513.5-bit classical preimage → ~256-bit post-quantum
 * (Grover) — 256-bit quantum is the bar; 162T (~257 bits) could
 * never reach it since Grover halves the space.
 *
 * The first 162 trits double as the routing address — the route is
 * a verifiable PREFIX of the identity, not a fabrication.
 *
 * @param {Buffer|Uint8Array} digest - 64-byte sealed AVOTH output
 * @returns {string} Full 324T address, six 54-trit tiers, each six
 *   colon-grouped 9-trit sub-blocks, dots between tiers ('T' = -1)
 */
function digestToTritAddress(digest) {
  let n = BigInt(`0x${Buffer.from(digest).toString('hex')}`);
  const trits = new Array(324);
  for (let i = 323; i >= 0; i--) {
    const r = Number(n % 3n); n /= 3n;
    trits[i] = r === 2 ? 'T' : String(r);
  }
  const out = [];
  for (let i = 0; i < 324; i++) {
    if (i > 0) out.push(i % 54 === 0 ? '.' : i % 9 === 0 ? ':' : '');
    out.push(trits[i]);
  }
  return out.join('');
}

/**
 * Derive the persistentId from the persistent public key — PUBLICLY
 * VERIFIABLE via the AVOTH-191 wormhole seal:
 *
 *   seal   = first 4 quats of AVOTH("yakmesh:pid:v4:{pkHex}")   (public)
 *   digest = AVOTH_sealed("YAKMESH|PID|v4|" ‖ pk, seal)         (pos-191 bound)
 *   pid    = "yak-" ‖ 324T(digest)   — injective base-3, all 512 bits
 *
 * The seal rides position 191 read-never-written through all 24
 * rounds, so the digest is structurally bound to the pid domain —
 * given (pid, pubkey) anyone recomputes and compares. Possession of
 * the persistent key then proves personhood via signature.
 *
 * @param {Uint8Array} publicKey - Persistent ML-DSA-65 public key
 * @returns {string} "yak-<full 324T>" persistent identifier
 */
export function persistentIdFromPublicKey(publicKey) {
  const pkHex = bytesToHex(publicKey);
  const seal = contextSeal(`yakmesh:pid:v4:${pkHex}`);
  if (!seal) throw new Error('AVOTH substrate unavailable — cannot derive persistentId');
  const digest = avothHashSealed(
    Buffer.concat([Buffer.from('YAKMESH|PID|v4|'), Buffer.from(publicKey)]), seal);
  if (!digest) throw new Error('AVOTH sealed hash failed — cannot derive persistentId');
  return `${PERSISTENT_ID_PREFIX}-${digestToTritAddress(digest)}`;
}

/**
 * Compute persistent machine ID — the 324T ternary address of the
 * persistent public key under the pid-domain wormhole seal (injective
 * base-3 of the full 512-bit digest — ~256-bit post-quantum preimage).
 * CONSTANT across all code upgrades, key rotations, and hardware
 * migration (mnemonic → seed → same persistent key → same pid).
 *
 * @param {Uint8Array} seed - Raw 32-byte machine seed
 * @returns {string} Persistent 324T identifier "yak-<324T>"
 */
function computePersistentId(seed) {
  return persistentIdFromPublicKey(persistentKeyPair(seed).publicKey);
}

/**
 * The canonical personhood-binding payload the persistent key signs:
 * pid → claim nodeId → epoch. Epoch binding makes the signature
 * per-epoch — a captured binding can't be replayed into another claim.
 */
export function pidBindString(persistentId, nodeId, epoch) {
  return `YAKMESH|PID-BIND|v1|${persistentId}|${nodeId}|${epoch}`;
}

/**
 * Verify a claim's personhood binding: { persistentId, persistentPubkey,
 * persistentSig } over `YAKMESH|PID-BIND|v1|{pid}|{nodeId}|{epoch}`.
 *
 * Both legs must hold: the pid must RE-DERIVE from the carried pubkey
 * (wormhole-sealed AVOTH — no lookup, no trust) and the signature must
 * verify under that key. A claim carrying a broken binding has NO
 * proven personhood — the triple is stripped, the claim itself stands
 * on its other evidence.
 */
export function verifyPersistentBinding({ persistentId, persistentPubkey, persistentSig }, nodeId, epoch) {
  try {
    if (typeof persistentId !== 'string' || !persistentId.startsWith(`${PERSISTENT_ID_PREFIX}-`)
        || typeof persistentPubkey !== 'string' || typeof persistentSig !== 'string') return false;
    const pk = hexToBytes(persistentPubkey);
    if (persistentIdFromPublicKey(pk) !== persistentId) return false;
    return ml_dsa65.verify(hexToBytes(persistentSig),
      new TextEncoder().encode(pidBindString(persistentId, nodeId, epoch)), pk);
  } catch { return false; }
}

/**
 * Compute a service persistent ID — a 324T identity for a named issuer
 * authority hosted on this machine (e.g. a game's work-issuer DOKO).
 * Anchored to the host's persistent public key so a service's identity
 * inherits the machine's personhood; distinct 'yaks-' namespace so a
 * service id is never accepted where a machine identity is expected.
 *
 * @param {Uint8Array} seed - Raw 32-byte machine seed
 * @param {string} serviceName - Issuer scope, e.g. 'work-issuer'
 * @returns {string} Persistent 324T identifier ('yaks-' namespace)
 */
export function computeServicePersistentId(seed, serviceName) {
  const pk = persistentKeyPair(seed).publicKey;
  const ctx = `yakmesh:service-id:v3:${serviceName}:${bytesToHex(pk)}`;
  const seal = contextSeal(ctx);
  if (!seal) throw new Error('AVOTH substrate unavailable — cannot derive service id');
  const payload = Buffer.concat([
    Buffer.from('YAKMESH|SERVICE-ID|v3|'), Buffer.from(serviceName),
    Buffer.from('|'), Buffer.from(pk)]);
  const digest = avothHashSealed(payload, seal);
  if (!digest) throw new Error('AVOTH sealed hash failed — cannot derive service id');
  return `${SERVICE_ID_PREFIX}-${digestToTritAddress(digest)}`;
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
// MNEMONIC BACKUP / RECOVERY (QUANTUM_WORDLIST)
// =============================================================================

/**
 * Convert raw seed bytes to a mnemonic phrase using QUANTUM_WORDLIST.
 * Each byte (0-255) maps to one of the 256 words in QUANTUM_WORDLIST.
 * 32 bytes → 32 words.
 * 
 * The last word is a YPC-27-derived checksum word for integrity verification.
 * Total output: 33 words (32 seed + 1 checksum).
 * 
 * @param {Uint8Array} seed - Raw 32-byte seed
 * @returns {string[]} Array of 33 mnemonic words
 */
function seedToMnemonic(seed) {
  if (!seed || seed.length !== SEED_BYTES) {
    throw new Error(`Seed must be ${SEED_BYTES} bytes, got ${seed?.length}`);
  }

  const words = [];
  for (let i = 0; i < seed.length; i++) {
    words.push(QUANTUM_WORDLIST[seed[i]]);
  }

  // Append YPC-27-derived checksum word
  const checksumHash = sha3_256(seed);
  const checksumByte = checksumHash[0]; // First byte of SHA3-256 of seed
  words.push(QUANTUM_WORDLIST[checksumByte]);

  return words;
}

/**
 * Convert a mnemonic phrase back to raw seed bytes.
 * Verifies the checksum word (33rd word) matches.
 * 
 * @param {string[]} words - Array of 33 mnemonic words
 * @returns {Uint8Array} Raw 32-byte seed
 * @throws {Error} If words are invalid or checksum fails
 */
function mnemonicToSeed(words) {
  if (!Array.isArray(words) || words.length !== SEED_BYTES + 1) {
    throw new Error(`Mnemonic must be ${SEED_BYTES + 1} words, got ${words?.length}`);
  }

  // Build reverse lookup map
  const wordToIndex = new Map();
  for (let i = 0; i < QUANTUM_WORDLIST.length; i++) {
    wordToIndex.set(QUANTUM_WORDLIST[i].toLowerCase(), i);
  }

  const seedBytes = new Uint8Array(SEED_BYTES);
  for (let i = 0; i < SEED_BYTES; i++) {
    const word = words[i].toLowerCase().trim();
    const idx = wordToIndex.get(word);
    if (idx === undefined) {
      throw new Error(`Unknown mnemonic word at position ${i + 1}: "${words[i]}"`);
    }
    seedBytes[i] = idx;
  }

  // Verify checksum word
  const checksumWord = words[SEED_BYTES].toLowerCase().trim();
  const checksumIdx = wordToIndex.get(checksumWord);
  if (checksumIdx === undefined) {
    throw new Error(`Unknown checksum word: "${words[SEED_BYTES]}"`);
  }

  const expectedHash = sha3_256(seedBytes);
  const expectedByte = expectedHash[0];
  if (checksumIdx !== expectedByte) {
    throw new Error(
      'Mnemonic checksum verification FAILED. ' +
      'One or more words may be incorrect or in the wrong order.'
    );
  }

  return seedBytes;
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
 * Contents: { encryptedSeed, ypc27Checksum, persistentId, migrationChain[], sstFamilies, schemaVersion }
 * NEVER stored: raw seed, private keys
 * 
 * The persistentId is constant across ALL code upgrades — it identifies
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
    this.persistentId = null;  // 324T persistent identity (constant across upgrades)
    this.persistentKeys = null; // ML-DSA-65 persistent identity keypair (in-memory only)
    this.migrationChain = [];  // History of (oracleHash, pubKeyHash) pairs
    this.sstFamilies = null;   // SST family analysis
    this.created = false;      // True if seed was just generated (first run)
    this.seedReset = null;     // Set when an unusable seed was quarantined + reminted
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
   * Write the seed file, tolerating read-only modes left by file guardians.
   * Guardians lock identity files to 0400 between restarts; restore write
   * permission before overwriting, then re-secure to 0600.
   */
  _writeSeedFile(seedFile) {
    if (platform() !== 'win32' && existsSync(this.seedPath)) {
      try { chmodSync(this.seedPath, 0o600); } catch { /* ignore */ }
    }
    writeFileSync(this.seedPath, JSON.stringify(seedFile, null, 2));
    this._secureFile();
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

      // Decrypt seed using hardware-derived key (realpath-bound).
      // Pre-realpath seeds were encrypted with the literal dataDir string —
      // fall back to that key once, then re-seal under the realpath key.
      let seed;
      try {
        seed = decryptSeed(data.encryptedSeed, this.dataDir);
      } catch (primaryErr) {
        const cpuModel = cpus()[0]?.model || 'unknown-cpu';
        const legacyFingerprint = `yakmesh:machine-seed:${hostname()}:${platform()}:${cpuModel}:${this.dataDir}`;
        const salt = sha3_256(new TextEncoder().encode('yakmesh-hardware-salt-2026'));
        const legacyKey = scryptSync(legacyFingerprint, Buffer.from(salt), 32, {
          N: 16384, r: 8, p: 1,
        });
        const decipher = createDecipheriv(
          'aes-256-gcm', legacyKey, Buffer.from(data.encryptedSeed.nonce, 'hex'),
        );
        decipher.setAuthTag(Buffer.from(data.encryptedSeed.tag, 'hex'));
        seed = new Uint8Array(Buffer.concat([
          decipher.update(Buffer.from(data.encryptedSeed.ciphertext, 'hex')),
          decipher.final(),
        ]));
        log.info('Machine seed migrated to realpath binding');
        this._reboundSeed = true;
      }

      // Verify YPC-27² integrity checksum. Files below SCHEMA_VERSION predate
      // the quadratic seal — accept the legacy linear checksum exactly once,
      // then re-seal under YPC-27² below. Current-schema files accept only
      // the dual-position quadratic checksum.
      const checksumOk = data.schemaVersion >= SCHEMA_VERSION
        ? verifySeedChecksum(seed, data.ypc27Checksum)
        : verifySeedChecksumLegacy(seed, data.ypc27Checksum);
      if (!checksumOk) {
        log.error('🚨 YPC-27 SEED INTEGRITY CHECK FAILED — possible tampering!');
        log.error('Seed checksum does not match. The seed file may have been modified.');
        log.error('Refusing to use potentially compromised seed.');
        throw new Error(
          'YPC-27 seed integrity check failed. Seed file may be tampered. ' +
          'Delete machine-seed.json to generate a new identity (reputation will be lost).'
        );
      }

      this.seed = seed;
      this._bindPersistentIdentity(seed); // always re-derive (324T; stored pid ignored)
      this.migrationChain = data.migrationChain || [];
      this.sstFamilies = data.sstFamilies || analyzeSeedFamilies(seed);
      this.created = false;

      // Schema migration: upgrade to v4 (324T persistent ID + YPC-27² seed
      // seal), or re-seal under the realpath-bound key after a legacy-binding
      // fallback.
      if (data.schemaVersion < SCHEMA_VERSION || !data.persistentId || this._reboundSeed) {
        if (!this._reboundSeed) log.info('Migrating seed file to v4 (324T persistentId, YPC-27² seal)');
        this._updateSeedFile();
        this._reboundSeed = false;
      }

      log.info('Machine seed loaded and verified', {
        ypc27: '✓',
        persistentId: this.persistentId,
        migrationEntries: this.migrationChain.length,
        sstFamilies: this.sstFamilies,
      });

      return true;
    } catch (e) {
      // An unusable seed can never become this machine's identity — a seed
      // that fails to decrypt was minted on different hardware (or a different
      // resolved dataDir), and a seed that fails its YPC-27 checksum is
      // tampered or corrupt. Either way: quarantine the file (preserved for
      // forensics / mnemonic recovery, never deleted) and mint a fresh
      // hardware-bound identity. No foreign seed can be injected — it simply
      // fails to decrypt and is replaced. The OLD persistentId is
      // unrecoverable by design; only a mnemonic restore can bring it back.
      const reason = e.message.includes('YPC-27') ? 'integrity-failed' : 'undecryptable';
      const quarantinePath = this.seedPath.replace(
        /\.json$/, `.invalid-${reason}-${Date.now()}.json`
      );
      try {
        renameSync(this.seedPath, quarantinePath);
      } catch (qe) {
        log.error('Could not quarantine bad seed file', { error: qe.message });
      }

      if (reason === 'integrity-failed') {
        log.error('🚨 YPC-27 SEED INTEGRITY CHECK FAILED — seed file tampered or corrupt.');
        log.error(`Quarantined to ${quarantinePath}. Minting a fresh hardware-bound identity.`);
        log.error('The previous persistentId is NOT recoverable without the mnemonic backup.');
      } else {
        log.warn('Machine seed cannot be decrypted on this hardware', { error: e.message });
        log.warn(`Foreign or relocated seed quarantined to ${quarantinePath}`);
        log.warn('Minting a fresh hardware-bound identity — a new persistentId will be assigned.');
      }

      this.seedReset = { reason, quarantinedTo: quarantinePath, at: new Date().toISOString() };
      return this._generateNew();
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

    // Compute YPC-27 integrity checksum (SHA3-hard polynomial seal)
    const ypc27Checksum = computeSeedChecksum(seed);

    // Compute persistent 324T identity (constant across all upgrades)
    const persistentKeys = persistentKeyPair(seed);
    const persistentId = persistentIdFromPublicKey(persistentKeys.publicKey);

    // Compute SST family analysis
    const sstFamilies = analyzeSeedFamilies(seed);

    // Encrypt seed under hardware-derived key
    const encryptedSeed = encryptSeed(seed, this.dataDir);

    // Save seed file
    const seedFile = {
      schemaVersion: SCHEMA_VERSION,
      encryptedSeed,
      ypc27Checksum,
      persistentId,
      sstFamilies,
      migrationChain: [],
      createdAt: new Date().toISOString(),
    };

    this._writeSeedFile(seedFile);

    this.seed = seed;
    this.persistentId = persistentId;
    this.persistentKeys = persistentKeys;
    this.migrationChain = [];
    this.sstFamilies = sstFamilies;
    this.created = true;

    log.info('Machine seed generated and secured', {
      persistentId: persistentId,
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
    const persistentId = this.persistentId || computePersistentId(this.seed);
    const sstFamilies = this.sstFamilies || analyzeSeedFamilies(this.seed);

    const existing = existsSync(this.seedPath)
      ? JSON.parse(readFileSync(this.seedPath, 'utf8'))
      : {};

    const seedFile = {
      schemaVersion: SCHEMA_VERSION,
      encryptedSeed,
      ypc27Checksum,
      persistentId,
      sstFamilies,
      migrationChain: this.migrationChain,
      createdAt: existing.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    this._writeSeedFile(seedFile);
  }

  /**
   * Export the seed as a mnemonic phrase (33 QUANTUM_WORDLIST words).
   * 
   * The mnemonic is the ONLY way to recover this identity on new hardware.
   * It MUST be stored offline (paper, steel plate, etc.) — never digitally.
   * 
   * If a password is provided, the mnemonic words are additionally encrypted
   * with AES-256-GCM under a scrypt-derived key and returned as a hex blob.
   * Without a password, the raw word array is returned directly.
   * 
   * @param {string} [password] - Optional password to encrypt mnemonic output
   * @returns {{ words: string[], encrypted?: string }} Mnemonic words (+ encrypted blob if password given)
   */
  exportMnemonic(password) {
    if (!this.seed) {
      throw new Error('Machine seed not initialized. Call init() first.');
    }

    const words = seedToMnemonic(this.seed);

    const result = { words };

    if (password && typeof password === 'string' && password.length > 0) {
      // Derive encryption key from password (NOT the hardware key)
      const salt = randomBytes(16);
      const key = scryptSync(password, salt, 32, { N: 2 ** 17, r: 8, p: 1 });
      const nonce = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, nonce);
      const plaintext = words.join(' ');
      const encrypted = Buffer.concat([
        cipher.update(Buffer.from(plaintext, 'utf8')),
        cipher.final(),
      ]);
      const tag = cipher.getAuthTag();

      // When password is provided, return ONLY the encrypted blob — not the raw words.
      // The password protects the mnemonic; returning both would defeat the purpose.
      result.encrypted = [
        salt.toString('hex'),
        nonce.toString('hex'),
        tag.toString('hex'),
        encrypted.toString('hex'),
      ].join(':');
      delete result.words;
    }

    log.info('Mnemonic exported', {
      wordCount: words.length,
      passwordProtected: !!password,
      persistentId: this.persistentId,
    });

    return result;
  }

  /**
   * Verify a mnemonic phrase against this machine's seed.
   * Compares the mnemonic-derived seed with the in-memory seed.
   * 
   * @param {string[]} words - Array of 33 mnemonic words to verify
   * @returns {{ valid: boolean, error?: string }}
   */
  verifyMnemonic(words) {
    if (!this.seed) {
      return { valid: false, error: 'Machine seed not initialized. Call init() first.' };
    }

    try {
      const recoveredSeed = mnemonicToSeed(words);

      // Constant-time comparison to prevent timing attacks
      if (recoveredSeed.length !== this.seed.length) {
        return { valid: false, error: 'Recovered seed length mismatch' };
      }

      let diff = 0;
      for (let i = 0; i < recoveredSeed.length; i++) {
        diff |= recoveredSeed[i] ^ this.seed[i];
      }

      if (diff !== 0) {
        return { valid: false, error: 'Mnemonic does not match current machine seed' };
      }

      return { valid: true };
    } catch (e) {
      return { valid: false, error: e.message };
    }
  }

  /**
   * Decrypt an encrypted mnemonic blob and verify it.
   * 
   * @param {string} encryptedBlob - The encrypted hex blob from exportMnemonic()
   * @param {string} password - Password used during export
   * @returns {string[]} Array of 33 mnemonic words
   */
  static decryptMnemonic(encryptedBlob, password) {
    const [saltHex, nonceHex, tagHex, ciphertextHex] = encryptedBlob.split(':');
    if (!saltHex || !nonceHex || !tagHex || !ciphertextHex) {
      throw new Error('Invalid encrypted mnemonic format');
    }

    const key = scryptSync(password, Buffer.from(saltHex, 'hex'), 32, { N: 2 ** 17, r: 8, p: 1 });
    const decipher = createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(nonceHex, 'hex'),
    );
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(ciphertextHex, 'hex')),
      decipher.final(),
    ]);

    return decrypted.toString('utf8').split(' ');
  }

  /**
   * Restore a machine seed from a mnemonic phrase on new hardware.
   * Creates a new seed file encrypted under the NEW machine's hardware key.
   * The persistent identity (persistentId) will be the SAME because
   * it's derived deterministically from the seed.
   * 
   * @param {string[]} words - Array of 33 mnemonic words
   * @param {string} dataDir - Data directory on the new machine
   * @returns {MachineSeed} Initialized MachineSeed instance
   */
  static importFromMnemonic(words, dataDir = './data') {
    // Convert mnemonic back to raw seed (validates checksum)
    const seed = mnemonicToSeed(words);

    // Verify YPC-27 integrity (the seed must produce a valid checksum)
    const ypc27Checksum = computeSeedChecksum(seed);
    const persistentKeys = persistentKeyPair(seed);
    const persistentId = persistentIdFromPublicKey(persistentKeys.publicKey);
    const sstFamilies = analyzeSeedFamilies(seed);

    // Ensure data directory exists
    if (!existsSync(dataDir)) {
      mkdirSync(dataDir, { recursive: true });
    }

    const seedPath = join(dataDir, SEED_FILENAME);
    if (existsSync(seedPath)) {
      throw new Error(
        'Seed file already exists at this location. ' +
        'Delete the existing seed file first if you want to import. ' +
        'WARNING: This will permanently lose the existing identity!'
      );
    }

    // Encrypt seed under NEW machine's hardware-derived key
    const encryptedSeed = encryptSeed(seed, dataDir);

    const seedFile = {
      schemaVersion: SCHEMA_VERSION,
      encryptedSeed,
      ypc27Checksum,
      persistentId,
      sstFamilies,
      migrationChain: [],
      createdAt: new Date().toISOString(),
      restoredFromMnemonic: true,
      restoredAt: new Date().toISOString(),
    };

    writeFileSync(seedPath, JSON.stringify(seedFile, null, 2));

    // Set permissions (no-op on Windows)
    if (platform() !== 'win32') {
      try { chmodSync(seedPath, 0o600); } catch { /* ignore */ }
    }

    // Create and return a ready MachineSeed instance
    const instance = new MachineSeed(dataDir);
    instance.seed = seed;
    instance.persistentId = persistentId;
    instance.persistentKeys = persistentKeys;
    instance.migrationChain = [];
    instance.sstFamilies = sstFamilies;
    instance.created = false;

    log.info('Identity restored from mnemonic', {
      persistentId: persistentId,
      ypc27Checksum: ypc27Checksum.slice(0, 12) + '...',
      sstFamilies,
      restoredAt: new Date().toISOString(),
    });

    return instance;
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
   * Derive the persistent identity keypair + pid for a seed and bind
   * them to this instance. Called wherever `this.seed` is assigned.
   * @param {Uint8Array} seed
   * @private
   */
  _bindPersistentIdentity(seed) {
    this.persistentKeys = persistentKeyPair(seed);
    this.persistentId = persistentIdFromPublicKey(this.persistentKeys.publicKey);
  }

  /**
   * Get the persistent 324T machine identity.
   * This ID is CONSTANT across all code upgrades — it identifies the
   * person (seed holder) regardless of network version, hardware, or
   * current node key.
   *
   * Format: "yak-<full 324T>" — publicly verifiable: the pid is the
   * injective base-3 expansion of the wormhole-sealed AVOTH digest of
   * the persistent public key (~513-bit space → ~256-bit post-quantum).
   *
   * @returns {string} Persistent 324T identifier
   */
  getPersistentId() {
    if (!this.persistentId) {
      throw new Error('Machine seed not initialized. Call init() first.');
    }
    return this.persistentId;
  }

  /**
   * The persistent identity — { persistentId, publicKey (hex),
   * sign(message) }. The persistent key signs ONLY personhood
   * bindings (pid → node_id → fp → epoch); never routine traffic.
   * @returns {{ persistentId: string, publicKey: string, sign: (m: Uint8Array|string) => string }}
   */
  getPersistentIdentity() {
    if (!this.persistentKeys) {
      throw new Error('Machine seed not initialized. Call init() first.');
    }
    const sk = this.persistentKeys.secretKey;
    return {
      persistentId: this.persistentId,
      publicKey: bytesToHex(this.persistentKeys.publicKey),
      // ml_dsa65.sign takes (message, secretKey)
      sign: (m) => bytesToHex(ml_dsa65.sign(
        typeof m === 'string' ? new TextEncoder().encode(m) : m, sk)),
    };
  }

  /**
   * Check if seed was just created (first run).
   * @returns {boolean}
   */
  isFirstRun() {
    return this.created;
  }

  /**
   * Get info about an automatic identity reset, if one occurred this boot.
   * @returns {{ reason: string, quarantinedTo: string, at: string } | null}
   */
  getResetInfo() {
    return this.seedReset;
  }
}

export default MachineSeed;
export { seedToMnemonic, mnemonicToSeed };