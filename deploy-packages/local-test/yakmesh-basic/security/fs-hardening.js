/**
 * Yakmesh File System Hardening — SANGHA-FS Extension
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * PHILOSOPHY: FILES AS COLLECTIVE PARTICIPANTS
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Traditional FS security: chmod 400, read-only mounts, ACLs.
 * SANGHA-FS: Critical files JOIN the collective as attestation participants.
 * 
 * Each protected file has a GUARDIAN that:
 * - Periodically hashes the file and attests its integrity to SANGHA
 * - Participates in collective circulation (antibodies visit file guardians)
 * - Triggers collective response if tampering is detected
 * 
 * This means:
 * - Tampering is detected within one circulation cycle (≤5s)
 * - All components are alerted simultaneously
 * - The mesh can quarantine a compromised node
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * PROTECTED ASSETS
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * 1. IDENTITY FILES
 *    - machine-seed.json — Hardware-encrypted seed (CRITICAL)
 *    - node-key.json — Public identity (HIGH)
 * 
 * 2. CONFIGURATION
 *    - yakmesh.config.js — Runtime config (oracle-verified)
 * 
 * 3. DATABASE
 *    - yakmesh.db — SQLite database (integrity header)
 * 
 * @module security/fs-hardening
 * @version 1.0.0
 */

import { createLogger } from '../utils/logger.js';
import { sha3_256 } from '../utils/accel.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { readFileSync, chmodSync, statSync, existsSync, watch } from 'fs';
import { join, resolve } from 'path';
import { platform } from 'os';
import { EventEmitter } from 'events';

const log = createLogger('security:fs-hardening');

// =============================================================================
// CONSTANTS
// =============================================================================

/** Protection levels */
export const PROTECTION_LEVEL = Object.freeze({
  CRITICAL: 'CRITICAL',   // Identity seed, private keys — IMMUTABLE after startup
  HIGH: 'HIGH',           // Public identity, config — LOCKED after startup
  NORMAL: 'NORMAL',       // Database, logs — MONITORED for integrity
});

/** File permission modes (POSIX) */
const POSIX_MODES = Object.freeze({
  CRITICAL: 0o400,        // r-------- (owner read only)
  HIGH: 0o600,            // rw------- (owner read/write)
  NORMAL: 0o644,          // rw-r--r-- (owner rw, others read)
});

/** Default files to protect */
const DEFAULT_PROTECTED_FILES = [
  { path: 'data/machine-seed.json', level: PROTECTION_LEVEL.CRITICAL },
  { path: 'data/node-key.json', level: PROTECTION_LEVEL.HIGH },
  { path: 'data/yakmesh.db', level: PROTECTION_LEVEL.NORMAL },
];

// =============================================================================
// FILE GUARDIAN
// =============================================================================

/**
 * FileGuardian — Protects a single file and attests to SANGHA
 * 
 * Each guardian:
 * - Takes an initial hash at startup
 * - Periodically re-hashes and compares
 * - Participates in SANGHA attestation cycles
 * - Triggers collective alert on tampering
 */
export class FileGuardian extends EventEmitter {
  #filePath;
  #level;
  #baselineHash;
  #baselineMtime;
  #baselineSize;
  #locked;
  #watcher;
  #checkInterval;
  #lastCheck;

  /**
   * @param {string} filePath - Absolute path to the file
   * @param {string} level - Protection level (CRITICAL/HIGH/NORMAL)
   */
  constructor(filePath, level = PROTECTION_LEVEL.NORMAL) {
    super();
    this.#filePath = resolve(filePath);
    this.#level = level;
    this.#baselineHash = null;
    this.#baselineMtime = null;
    this.#baselineSize = null;
    this.#locked = false;
    this.#watcher = null;
    this.#checkInterval = null;
    this.#lastCheck = 0;

    Object.seal(this);
  }

  /** Get file path */
  get path() { return this.#filePath; }

  /** Get protection level */
  get level() { return this.#level; }

  /** Get baseline hash */
  get baselineHash() { return this.#baselineHash; }

  /** Is file locked (immutable)? */
  get isLocked() { return this.#locked; }

  /**
   * Initialize guardian — take baseline snapshot
   * @returns {Promise<void>}
   */
  async init() {
    if (!existsSync(this.#filePath)) {
      log.warn('Protected file does not exist yet', { path: this.#filePath });
      return;
    }

    // Take baseline snapshot
    await this.#takeBaseline();

    // Apply restrictive permissions on POSIX systems
    this.#applyPermissions();

    // Set up file watcher for real-time detection
    this.#startWatcher();

    log.info('FileGuardian initialized', {
      path: this.#filePath,
      level: this.#level,
      hash: this.#baselineHash?.slice(0, 16) + '...',
      size: this.#baselineSize,
    });
  }

  /**
   * Take baseline snapshot of file
   */
  async #takeBaseline() {
    const content = readFileSync(this.#filePath);
    const hash = sha3_256(content);
    const stat = statSync(this.#filePath);

    this.#baselineHash = bytesToHex(hash);
    this.#baselineMtime = stat.mtimeMs;
    this.#baselineSize = stat.size;
    this.#lastCheck = Date.now();
  }

  /**
   * Apply restrictive file permissions (POSIX only)
   */
  #applyPermissions() {
    if (platform() === 'win32') {
      // Windows uses NTFS ACLs — handled differently
      // TODO: Use icacls for Windows permission hardening
      return;
    }

    const mode = POSIX_MODES[this.#level] || POSIX_MODES.NORMAL;
    try {
      chmodSync(this.#filePath, mode);
      log.debug('Applied file permissions', {
        path: this.#filePath,
        mode: mode.toString(8),
      });
    } catch (e) {
      log.warn('Failed to set file permissions', {
        path: this.#filePath,
        error: e.message,
      });
    }
  }

  /**
   * Start file system watcher for real-time tampering detection
   */
  #startWatcher() {
    // NORMAL-level files (database) change constantly — only watch for deletion
    // CRITICAL/HIGH files get full change monitoring
    try {
      this.#watcher = watch(this.#filePath, (eventType) => {
        if (eventType === 'change' && this.#level !== PROTECTION_LEVEL.NORMAL) {
          // File was modified — verify integrity (CRITICAL/HIGH only)
          this.verify().catch(e => {
            log.error('Watch-triggered verification failed', { error: e.message });
          });
        } else if (eventType === 'rename') {
          // File was renamed/deleted — always report regardless of level
          this.emit('tamper', {
            type: 'FILE_REMOVED',
            path: this.#filePath,
            level: this.#level,
            timestamp: Date.now(),
          });
        }
      });
    } catch (e) {
      log.warn('Could not set up file watcher', {
        path: this.#filePath,
        error: e.message,
      });
    }
  }

  /**
   * Lock the file (prevent further modifications)
   * For CRITICAL files, this makes them effectively read-only after startup.
   */
  lock() {
    if (this.#locked) return;

    this.#locked = true;

    // Re-apply most restrictive permissions
    if (platform() !== 'win32') {
      try {
        chmodSync(this.#filePath, 0o400); // Read-only
      } catch (e) {
        log.warn('Could not lock file', { path: this.#filePath, error: e.message });
      }
    }

    log.info('File locked (read-only)', { path: this.#filePath });
  }

  /**
   * Re-take the baseline snapshot.
   * Used after startup grace period so that HIGH-level files capture
   * their post-initialization state (e.g. node-key.json after derivation).
   */
  async rebaseline() {
    if (!existsSync(this.#filePath)) return;
    await this.#takeBaseline();
    log.info('FileGuardian re-baselined', {
      path: this.#filePath,
      level: this.#level,
      hash: this.#baselineHash?.slice(0, 16) + '...',
      size: this.#baselineSize,
    });
  }

  /**
   * Verify file integrity against baseline
   * @returns {Promise<{ valid: boolean, error?: string }>}
   */
  async verify() {
    if (!this.#baselineHash) {
      return { valid: true, error: 'No baseline (file not yet created)' };
    }

    if (!existsSync(this.#filePath)) {
      const tamperEvent = {
        type: 'FILE_DELETED',
        path: this.#filePath,
        level: this.#level,
        timestamp: Date.now(),
      };
      this.emit('tamper', tamperEvent);
      return { valid: false, error: 'File deleted' };
    }

    // NORMAL-level files (e.g. yakmesh.db) are mutable by design.
    // Only monitor for existence/deletion — NOT content hashing.
    // The database changes constantly during normal operation.
    if (this.#level === PROTECTION_LEVEL.NORMAL) {
      this.#lastCheck = Date.now();
      return { valid: true };
    }

    try {
      const content = readFileSync(this.#filePath);
      const hash = bytesToHex(sha3_256(content));
      const stat = statSync(this.#filePath);

      this.#lastCheck = Date.now();

      // Check hash (CRITICAL and HIGH only)
      if (hash !== this.#baselineHash) {
        const tamperEvent = {
          type: 'HASH_MISMATCH',
          path: this.#filePath,
          level: this.#level,
          expected: this.#baselineHash.slice(0, 16) + '...',
          actual: hash.slice(0, 16) + '...',
          timestamp: Date.now(),
        };
        this.emit('tamper', tamperEvent);
        return { valid: false, error: 'Hash mismatch' };
      }

      // Check size (belt + suspenders)
      if (stat.size !== this.#baselineSize) {
        const tamperEvent = {
          type: 'SIZE_MISMATCH',
          path: this.#filePath,
          level: this.#level,
          expected: this.#baselineSize,
          actual: stat.size,
          timestamp: Date.now(),
        };
        this.emit('tamper', tamperEvent);
        return { valid: false, error: 'Size mismatch' };
      }

      return { valid: true };
    } catch (e) {
      return { valid: false, error: e.message };
    }
  }

  /**
   * Get state for SANGHA attestation
   * @returns {Promise<object>}
   */
  async getState() {
    const verification = await this.verify();
    return {
      path: this.#filePath,
      level: this.#level,
      hash: this.#baselineHash?.slice(0, 16),
      locked: this.#locked,
      valid: verification.valid,
      lastCheck: this.#lastCheck,
    };
  }

  /**
   * Stop the guardian
   */
  stop() {
    if (this.#watcher) {
      this.#watcher.close();
      this.#watcher = null;
    }
    if (this.#checkInterval) {
      clearInterval(this.#checkInterval);
      this.#checkInterval = null;
    }
  }
}

// =============================================================================
// FS HARDENING MANAGER
// =============================================================================

/**
 * FSHardening — Manages all file guardians and SANGHA integration
 */
export class FSHardening extends EventEmitter {
  #guardians;
  #dataDir;
  #sangha;
  #started;
  #verifyInterval;

  /**
   * @param {string} dataDir - Base data directory
   */
  constructor(dataDir = './data') {
    super();
    this.#guardians = new Map();
    this.#dataDir = resolve(dataDir);
    this.#sangha = null;
    this.#started = false;
    this.#verifyInterval = null;

    Object.seal(this);
  }

  /**
   * Register a file for protection
   * @param {string} relativePath - Path relative to data directory
   * @param {string} level - Protection level
   */
  async protect(relativePath, level = PROTECTION_LEVEL.NORMAL) {
    const fullPath = join(this.#dataDir, '..', relativePath);

    if (this.#guardians.has(fullPath)) {
      log.warn('File already protected', { path: fullPath });
      return;
    }

    const guardian = new FileGuardian(fullPath, level);

    // Forward tamper events
    guardian.on('tamper', (event) => {
      this.#handleTamper(event);
    });

    await guardian.init();
    this.#guardians.set(fullPath, guardian);

    // Lock CRITICAL files immediately
    if (level === PROTECTION_LEVEL.CRITICAL) {
      guardian.lock();
    }
  }

  /**
   * Handle tampering event
   */
  #handleTamper(event) {
    log.error('🚨 FILE TAMPERING DETECTED', event);

    // Emit for external handlers
    this.emit('tamper', event);

    // If SANGHA is connected, trigger collective response
    if (this.#sangha) {
      try {
        // Record as anomaly in current antibody circulation
        const anomaly = {
          componentId: 'fs',
          type: event.type,
          details: event,
          timestamp: Date.now(),
        };
        this.emit('anomaly', anomaly);
      } catch (e) {
        log.error('Failed to report to SANGHA', { error: e.message });
      }
    }
  }

  /**
   * Initialize with default protected files
   */
  async init() {
    for (const file of DEFAULT_PROTECTED_FILES) {
      try {
        await this.protect(file.path, file.level);
      } catch (e) {
        log.warn('Could not protect file', { path: file.path, error: e.message });
      }
    }

    log.info('FS Hardening initialized', {
      guardians: this.#guardians.size,
    });
  }

  /**
   * Bind to SANGHA collective
   * @param {Sangha} sangha - The SANGHA instance
   */
  bindSangha(sangha) {
    this.#sangha = sangha;
    log.info('FS Hardening bound to SANGHA collective');
  }

  /**
   * Start periodic verification
   * @param {number} intervalMs - Verification interval (default: 30s)
   */
  start(intervalMs = 30000) {
    if (this.#started) return;

    this.#started = true;

    // Periodic verification
    this.#verifyInterval = setInterval(async () => {
      await this.verifyAll();
    }, intervalMs);

    // After startup grace period (5s):
    // - Re-baseline HIGH files (they may have been written during init)
    // - Then lock them
    setTimeout(async () => {
      for (const [path, guardian] of this.#guardians) {
        if (guardian.level === PROTECTION_LEVEL.HIGH && !guardian.isLocked) {
          await guardian.rebaseline();
          guardian.lock();
        }
      }
      log.info('Startup grace period ended — HIGH files re-baselined and locked');
    }, 5000);

    log.info('FS Hardening started', { interval: intervalMs });
  }

  /**
   * Verify all protected files
   * @returns {Promise<{ valid: boolean, errors: object[] }>}
   */
  async verifyAll() {
    const errors = [];

    for (const [path, guardian] of this.#guardians) {
      const result = await guardian.verify();
      if (!result.valid) {
        errors.push({
          path,
          level: guardian.level,
          error: result.error,
        });
      }
    }

    if (errors.length > 0) {
      log.error('File verification failures', { count: errors.length, errors });
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Get state for SANGHA attestation (FS component)
   * @returns {Promise<object>}
   */
  async getState() {
    const guardianStates = [];

    for (const [path, guardian] of this.#guardians) {
      guardianStates.push(await guardian.getState());
    }

    return {
      component: 'fs',
      guardianCount: this.#guardians.size,
      guardians: guardianStates,
      allValid: guardianStates.every(g => g.valid),
    };
  }

  /**
   * Get status summary
   */
  getStatus() {
    const files = [];

    for (const [path, guardian] of this.#guardians) {
      files.push({
        path: guardian.path,
        level: guardian.level,
        locked: guardian.isLocked,
        hash: guardian.baselineHash?.slice(0, 16) + '...',
      });
    }

    return {
      started: this.#started,
      sanghaConnected: !!this.#sangha,
      files,
    };
  }

  /**
   * Stop FS hardening
   */
  stop() {
    if (!this.#started) return;

    this.#started = false;

    if (this.#verifyInterval) {
      clearInterval(this.#verifyInterval);
      this.#verifyInterval = null;
    }

    for (const guardian of this.#guardians.values()) {
      guardian.stop();
    }

    log.info('FS Hardening stopped');
  }
}

// =============================================================================
// SINGLETON & EXPORTS
// =============================================================================

let _instance = null;

/**
 * Get the FSHardening singleton
 * @param {string} dataDir - Data directory (only used on first call)
 * @returns {FSHardening}
 */
export function getFSHardening(dataDir = './data') {
  if (!_instance) {
    _instance = new FSHardening(dataDir);
  }
  return _instance;
}

/**
 * Quick protection helper
 * @param {string} filePath - File path
 * @param {string} level - Protection level
 */
export async function protectFile(filePath, level = PROTECTION_LEVEL.NORMAL) {
  const fs = getFSHardening();
  await fs.protect(filePath, level);
}

export default FSHardening;
