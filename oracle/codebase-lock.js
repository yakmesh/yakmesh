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
 * Codebase Lock Module
 * 
 * Prevents source code modification during runtime by opening exclusive
 * file handles on all source files. This is a critical security measure
 * for the Code Proof Protocol.
 * 
 * On Windows: Creates sharing violations for write access
 * On Unix: Removes write permissions during runtime
 * 
 * v1.3.0 ENHANCEMENTS:
 * - File system watchdog for tampering detection
 * - Tampering attempt logging and alerting
 * - Identity key file protection (chmod 400)
 * - Secure data directory permissions
 * 
 * @module CodebaseLock
 * @version 1.3.0
 */

import { openSync, closeSync, readdirSync, statSync, chmodSync, watch, existsSync } from 'fs';
import { join, extname, basename } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { createLogger } from '../utils/logger.js';
import { EventEmitter } from 'events';

const log = createLogger('oracle:codebase-lock');

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Directories to exclude (not source code)
const EXCLUDE_DIRS = new Set([
  'node_modules',
  '.git',
  'data',
  'database',
  'logs',
  '.vscode',
  'coverage',
  'dist',
  'build',
  'test-nodes',  // Test data
]);

// File extensions to lock (source files)
const SOURCE_EXTENSIONS = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.json',
  '.ts',
  '.tsx',
]);

// Files to exclude even with valid extensions
const EXCLUDE_FILES = new Set([
  'package-lock.json',
  '.env',
]);

// Identity/security files that need extra protection (chmod 400)
const CRITICAL_FILES = [
  'identity/node-key.json',
  'identity/private-key.pem',
  'data/node-identity.json',
];

// Directories containing sensitive data
const SECURE_DIRS = [
  'identity',
  'data',
];

/**
 * TamperEvent - emitted when tampering is detected
 */
export class TamperEvent {
  constructor(type, path, details = {}) {
    this.type = type;  // 'modify' | 'delete' | 'create' | 'rename'
    this.path = path;
    this.details = details;
    this.timestamp = Date.now();
    this.isoTime = new Date().toISOString();
  }
}

/**
 * CodebaseLock - Runtime file locking for source code protection
 * Now with tampering detection watchdog
 */
export class CodebaseLock extends EventEmitter {
  #handles = [];
  #locked = false;
  #rootDir = null;
  #isWindows = process.platform === 'win32';
  #originalPermissions = new Map();
  #watchers = [];
  #tamperEvents = [];
  #watchdogActive = false;

  constructor() {
    super();
    this.#rootDir = join(__dirname, '..');
  }

  /**
   * Lock all source files in the codebase
   * @returns {Object} Result with success status and file count
   */
  lock() {
    if (this.#locked) {
      return { success: true, fileCount: this.#handles.length, message: 'Already locked' };
    }

    try {
      const sourceFiles = this.#collectSourceFiles(this.#rootDir);

      for (const filePath of sourceFiles) {
        try {
          if (this.#isWindows) {
            // On Windows, open with read flag - creates sharing violation for write access
            const fd = openSync(filePath, 'r');
            this.#handles.push({ fd, path: filePath });
          } else {
            // On Unix, store original permissions and remove write
            const stats = statSync(filePath);
            const originalMode = stats.mode;
            this.#originalPermissions.set(filePath, originalMode);

            // Remove write permissions (keep read/execute)
            const newMode = originalMode & ~0o222;
            chmodSync(filePath, newMode);
            this.#handles.push({ path: filePath, originalMode });
          }
        } catch (e) {
          // If we can't lock a file, log but continue
          // Some files might already be locked or inaccessible
          log.warn('Could not lock file', { path: filePath, error: e.message });
        }
      }

      this.#locked = true;

      // Start watchdog for tampering detection
      this.#startWatchdog();

      // Protect critical identity files
      this.#protectCriticalFiles();

      return {
        success: true,
        fileCount: this.#handles.length,
        message: `Locked ${this.#handles.length} source files`,
        watchdogActive: this.#watchdogActive,
      };
    } catch (e) {
      return {
        success: false,
        error: e.message,
        fileCount: 0,
      };
    }
  }

  /**
   * Unlock all source files
   * @returns {Object} Result with success status
   */
  unlock() {
    if (!this.#locked) {
      return { success: true, message: 'Not locked' };
    }

    let errors = [];

    for (const handle of this.#handles) {
      try {
        if (this.#isWindows && handle.fd !== undefined) {
          // Close file descriptor on Windows
          closeSync(handle.fd);
        } else if (handle.originalMode !== undefined) {
          // Restore original permissions on Unix
          chmodSync(handle.path, handle.originalMode);
        }
      } catch (e) {
        errors.push(`${handle.path}: ${e.message}`);
      }
    }

    this.#handles = [];
    this.#originalPermissions.clear();
    this.#locked = false;

    // Stop watchdog
    this.#stopWatchdog();

    return {
      success: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
      message: 'Codebase unlocked',
    };
  }

  /**
   * Check if codebase is currently locked
   * @returns {boolean}
   */
  isLocked() {
    return this.#locked;
  }

  /**
   * Check if watchdog is active
   * @returns {boolean}
   */
  isWatchdogActive() {
    return this.#watchdogActive;
  }

  /**
   * Get tampering events (if any)
   * @returns {TamperEvent[]}
   */
  getTamperEvents() {
    return [...this.#tamperEvents];
  }

  /**
   * Clear tampering events after review
   */
  clearTamperEvents() {
    this.#tamperEvents = [];
  }

  /**
   * Get count of locked files
   * @returns {number}
   */
  getLockedFileCount() {
    return this.#handles.length;
  }

  /**
   * Collect all source files recursively
   * @private
   */
  #collectSourceFiles(dir, results = []) {
    try {
      const entries = readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        if (entry.isDirectory()) {
          // Skip excluded directories
          if (!EXCLUDE_DIRS.has(entry.name)) {
            this.#collectSourceFiles(fullPath, results);
          }
        } else if (entry.isFile()) {
          const ext = extname(entry.name).toLowerCase();

          // Include only source files, exclude specific files
          if (SOURCE_EXTENSIONS.has(ext) && !EXCLUDE_FILES.has(entry.name)) {
            results.push(fullPath);
          }
        }
      }
    } catch (e) {
      // Directory might not be readable
    }

    return results;
  }

  /**
   * Start file system watchdog for tampering detection
   * @private
   */
  #startWatchdog() {
    if (this.#watchdogActive) return;

    try {
      // Watch key directories for changes
      const dirsToWatch = ['server', 'oracle', 'security', 'mesh', 'identity', 'gossip'];

      for (const dirName of dirsToWatch) {
        const dirPath = join(this.#rootDir, dirName);
        if (!existsSync(dirPath)) continue;

        try {
          const watcher = watch(dirPath, { recursive: true }, (eventType, filename) => {
            if (!filename) return;

            // Only care about source files
            const ext = extname(filename).toLowerCase();
            if (!SOURCE_EXTENSIONS.has(ext)) return;

            const event = new TamperEvent(eventType, join(dirPath, filename), {
              directory: dirName,
              filename,
            });

            this.#tamperEvents.push(event);

            // Emit event for external handlers
            this.emit('tamper', event);

            // Log as critical security event
            log.error('⚠️ TAMPERING DETECTED', {
              type: eventType,
              file: filename,
              directory: dirName,
              timestamp: event.isoTime,
            });
          });

          this.#watchers.push(watcher);
        } catch (e) {
          log.warn('Could not watch directory', { dir: dirName, error: e.message });
        }
      }

      this.#watchdogActive = this.#watchers.length > 0;

      if (this.#watchdogActive) {
        log.info('Watchdog active', { directories: this.#watchers.length });
      }
    } catch (e) {
      log.warn('Watchdog failed to start', { error: e.message });
    }
  }

  /**
   * Stop file system watchdog
   * @private
   */
  #stopWatchdog() {
    for (const watcher of this.#watchers) {
      try {
        watcher.close();
      } catch (e) {
        // Ignore close errors
      }
    }
    this.#watchers = [];
    this.#watchdogActive = false;
  }

  /**
   * Protect critical identity and security files
   * Sets chmod 400 (read-only owner) on sensitive files
   * @private
   */
  #protectCriticalFiles() {
    if (this.#isWindows) {
      // Windows doesn't support Unix permissions in the same way
      // The file handle locking already provides protection
      return;
    }

    for (const relPath of CRITICAL_FILES) {
      const fullPath = join(this.#rootDir, relPath);

      if (!existsSync(fullPath)) continue;

      try {
        const stats = statSync(fullPath);

        // Store original permissions
        if (!this.#originalPermissions.has(fullPath)) {
          this.#originalPermissions.set(fullPath, stats.mode);
        }

        // Set to 0400 (read-only owner)
        chmodSync(fullPath, 0o400);

        log.info('Protected critical file', { path: relPath, mode: '0400' });
      } catch (e) {
        log.warn('Could not protect critical file', { path: relPath, error: e.message });
      }
    }

    // Secure data directories
    for (const dirName of SECURE_DIRS) {
      const dirPath = join(this.#rootDir, dirName);

      if (!existsSync(dirPath)) continue;

      try {
        // Set directory to 0700 (owner only)
        chmodSync(dirPath, 0o700);
        log.info('Secured directory', { path: dirName, mode: '0700' });
      } catch (e) {
        log.warn('Could not secure directory', { path: dirName, error: e.message });
      }
    }
  }
}

// Singleton instance
let codebaseLockInstance = null;

/**
 * Get the singleton CodebaseLock instance
 * @returns {CodebaseLock}
 */
export function getCodebaseLock() {
  if (!codebaseLockInstance) {
    codebaseLockInstance = new CodebaseLock();
  }
  return codebaseLockInstance;
}

/**
 * Lock the codebase (convenience function)
 * @returns {Object} Lock result
 */
export function lockCodebase() {
  return getCodebaseLock().lock();
}

/**
 * Unlock the codebase (convenience function)
 * @returns {Object} Unlock result
 */
export function unlockCodebase() {
  return getCodebaseLock().unlock();
}

/**
 * Set up automatic unlock on process exit
 */
export function setupUnlockOnExit() {
  const cleanup = () => {
    const lock = getCodebaseLock();
    if (lock.isLocked()) {
      log.info('Unlocking codebase on exit');
      lock.unlock();
    }
  };

  // Handle various exit signals
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(0); });
  process.on('SIGTERM', () => { cleanup(); process.exit(0); });
  // Transient network errors that are safe to ignore in a P2P mesh node.
  // These bubble up as uncaught exceptions when TCP connections are reset
  // by remote peers, timeouts occur, or connections are refused — all
  // normal in a mesh network. Crashing on these kills the node needlessly.
  const TRANSIENT_NETWORK_ERRORS = new Set([
    'ECONNRESET', 'EPIPE', 'ECONNREFUSED', 'ETIMEDOUT',
    'ECONNABORTED', 'EHOSTUNREACH', 'ENETUNREACH', 'EAI_AGAIN',
  ]);

  process.on('uncaughtException', (err) => {
    // Check if this is a transient network error
    if (err.code && TRANSIENT_NETWORK_ERRORS.has(err.code)) {
      log.warn('Transient network error (non-fatal)', { code: err.code, error: err.message });
      return; // Do NOT exit — these are normal in P2P mesh operation
    }
    log.error('Uncaught exception', { error: err.message, stack: err.stack });
    cleanup();
    process.exit(1);
  });
}

/**
 * Subscribe to tampering events
 * @param {Function} handler - Called with TamperEvent on tampering
 * @returns {Function} Unsubscribe function
 */
export function onTamper(handler) {
  const lock = getCodebaseLock();
  lock.on('tamper', handler);
  return () => lock.off('tamper', handler);
}

/**
 * Get any tampering events that occurred
 * @returns {TamperEvent[]}
 */
export function getTamperEvents() {
  return getCodebaseLock().getTamperEvents();
}

export default CodebaseLock;
