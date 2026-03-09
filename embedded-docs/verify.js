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
 * YAKMESH Documentation Verification
 * 
 * Mathematically verify documentation integrity using SHA3-256 hashes.
 * No network trust required - verification is local and instant.
 * 
 * @module embedded-docs/verify
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { BUNDLE_HASH, FILE_INDEX } from './bundle.js';

/**
 * Verify a single file's content matches its hash
 * 
 * @param {string} path - File path relative to docs root
 * @param {Buffer|Uint8Array|string} content - File content to verify
 * @returns {{valid: boolean, expected?: string, actual?: string, error?: string}}
 * 
 * @example
 * const result = verifyFile('index.html', fileContent);
 * if (!result.valid) {
 *   console.error(`Tampered file: ${result.error}`);
 * }
 */
export function verifyFile(path, content) {
  const expected = FILE_INDEX[path]?.hash;
  
  if (!expected) {
    return { 
      valid: false, 
      error: `File not in bundle: ${path}` 
    };
  }
  
  // Convert string to bytes if needed
  const bytes = typeof content === 'string' 
    ? new TextEncoder().encode(content) 
    : content;
  
  const actual = bytesToHex(sha3_256(bytes));
  
  return {
    valid: actual === expected,
    expected,
    actual,
    ...(actual !== expected && { error: `Hash mismatch for ${path}` })
  };
}

/**
 * Verify entire bundle integrity
 * 
 * All files must be provided and all hashes must match.
 * Returns true only if the entire bundle is verified.
 * 
 * @param {Record<string, Buffer|Uint8Array|string>} fileContents - Map of path -> content
 * @returns {{valid: boolean, bundleHash?: string, computed?: string, error?: string, verifiedCount?: number}}
 * 
 * @example
 * const files = {
 *   'index.html': fs.readFileSync('docs/index.html'),
 *   'docs.css': fs.readFileSync('docs/docs.css'),
 *   // ...all other files
 * };
 * const result = verifyBundle(files);
 * if (result.valid) {
 *   console.log(`Bundle verified: ${result.bundleHash}`);
 * }
 */
export function verifyBundle(fileContents) {
  const hashes = [];
  let verifiedCount = 0;
  
  // Verify each file in the index
  for (const [path, meta] of Object.entries(FILE_INDEX)) {
    const content = fileContents[path];
    
    if (content === undefined) {
      return { 
        valid: false, 
        error: `Missing file: ${path}`,
        verifiedCount 
      };
    }
    
    const result = verifyFile(path, content);
    
    if (!result.valid) {
      return { 
        valid: false, 
        error: result.error || `Tampered file: ${path}`,
        verifiedCount 
      };
    }
    
    hashes.push(result.actual);
    verifiedCount++;
  }
  
  // Check for extra files (not in bundle)
  const bundledPaths = new Set(Object.keys(FILE_INDEX));
  const providedPaths = Object.keys(fileContents);
  const extraFiles = providedPaths.filter(p => !bundledPaths.has(p));
  
  if (extraFiles.length > 0) {
    return {
      valid: false,
      error: `Extra files not in bundle: ${extraFiles.join(', ')}`,
      verifiedCount
    };
  }
  
  // Verify bundle hash = SHA3-256(sorted individual hashes joined)
  hashes.sort();
  const joinedHashes = hashes.join('');
  const computedBundleHash = bytesToHex(sha3_256(new TextEncoder().encode(joinedHashes)));
  
  if (computedBundleHash !== BUNDLE_HASH) {
    return {
      valid: false,
      error: 'Bundle hash mismatch - file hashes valid but bundle hash incorrect',
      bundleHash: BUNDLE_HASH,
      computed: computedBundleHash,
      verifiedCount
    };
  }
  
  return {
    valid: true,
    bundleHash: BUNDLE_HASH,
    computed: computedBundleHash,
    verifiedCount
  };
}

/**
 * Get bundle info without verification
 * 
 * @returns {{hash: string, fileCount: number, files: string[], version: string}}
 */
export function getBundleInfo() {
  const files = Object.keys(FILE_INDEX);
  
  return {
    hash: BUNDLE_HASH,
    fileCount: files.length,
    files,
    totalSize: Object.values(FILE_INDEX).reduce((sum, f) => sum + f.size, 0),
    // Import dynamically to avoid circular dependency
    version: '0.0.0', // Will be set properly by build script
  };
}

/**
 * Check if a path is in the bundle
 * 
 * @param {string} path - File path to check
 * @returns {boolean}
 */
export function isInBundle(path) {
  return path in FILE_INDEX;
}

/**
 * Get the expected hash for a file
 * 
 * @param {string} path - File path
 * @returns {string|null} Hash or null if not in bundle
 */
export function getExpectedHash(path) {
  return FILE_INDEX[path]?.hash || null;
}
