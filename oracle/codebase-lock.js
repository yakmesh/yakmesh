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
 * @module CodebaseLock
 * @version 1.2.0
 */

import { openSync, closeSync, readdirSync, statSync, chmodSync } from 'fs';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { createLogger } from '../utils/logger.js';

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

/**
 * CodebaseLock - Runtime file locking for source code protection
 */
export class CodebaseLock {
  #handles = [];
  #locked = false;
  #rootDir = null;
  #isWindows = process.platform === 'win32';
  #originalPermissions = new Map();
  
  constructor() {
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
      return { 
        success: true, 
        fileCount: this.#handles.length,
        message: `Locked ${this.#handles.length} source files`,
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
  process.on('uncaughtException', (err) => {
    log.error('Uncaught exception', { error: err.message, stack: err.stack });
    cleanup();
    process.exit(1);
  });
}

export default CodebaseLock;
