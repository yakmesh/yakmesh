#!/usr/bin/env node

/**
 * YAKMESH Documentation Bundle Generator
 * 
 * Reads website/docs/ and generates a hardcoded bundle with SHA3-256 
 * verification hashes. This bundle ships with the npm package.
 * 
 * Run: npm run build:docs
 * 
 * @author YAKMESH Team
 * @license MIT
 */

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync, mkdirSync, copyFileSync, rmSync } from 'fs';
import { join, relative, extname, dirname } from 'path';
import { fileURLToPath } from 'url';
import { deriveNetworkName } from '../oracle/network-identity.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, '..');
const WEBSITE_ROOT = join(PROJECT_ROOT, '..', 'website');
const DOCS_SOURCE = join(WEBSITE_ROOT, 'docs');
const ASSETS_SOURCE = join(WEBSITE_ROOT, 'assets');
const BUNDLE_OUTPUT = join(PROJECT_ROOT, 'embedded-docs', 'bundle.js');

// Internal docs copies that ship with the package
const INTERNAL_DOCS = [
  join(PROJECT_ROOT, 'docs'),
  join(PROJECT_ROOT, 'website', 'docs'),
];
const INTERNAL_ASSETS = join(PROJECT_ROOT, 'website', 'assets');

// Content type mapping
const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.json': 'application/json',
  '.txt': 'text/plain; charset=utf-8',
};

/**
 * Get content type for a file
 */
function getContentType(filePath) {
  const ext = extname(filePath).toLowerCase();
  return CONTENT_TYPES[ext] || 'application/octet-stream';
}

/**
 * Collect all files recursively from a directory
 */
function collectFiles(dir, base = dir, prefix = '') {
  const files = [];

  if (!existsSync(dir)) {
    console.warn(`⚠️  Directory not found: ${dir}`);
    return files;
  }

  for (const entry of readdirSync(dir)) {
    const fullPath = join(dir, entry);
    const stat = statSync(fullPath);

    if (stat.isDirectory()) {
      files.push(...collectFiles(fullPath, base, prefix));
    } else {
      // Get path relative to base, normalize slashes
      let relativePath = relative(base, fullPath).replace(/\\/g, '/');

      // Add prefix if specified (for assets)
      if (prefix) {
        relativePath = prefix + '/' + relativePath;
      }

      files.push({
        path: relativePath,
        fullPath,
        size: stat.size,
      });
    }
  }

  return files;
}

/**
 * Compute SHA3-256 hash of file content
 */
function hashFile(filePath) {
  const content = readFileSync(filePath);
  return bytesToHex(sha3_256(content));
}

/**
 * Mirror a source directory to a destination, syncing all files.
 * Creates directories as needed, copies changed files, removes extras.
 */
function mirrorDirectory(src, dest) {
  if (!existsSync(src)) return 0;
  mkdirSync(dest, { recursive: true });

  const srcFiles = collectFiles(src, src);
  const destFiles = existsSync(dest) ? collectFiles(dest, dest) : [];
  const destSet = new Set(destFiles.map(f => f.path));
  let copied = 0;

  for (const file of srcFiles) {
    const destPath = join(dest, file.path);
    mkdirSync(dirname(destPath), { recursive: true });

    // Copy if missing or different size
    if (!existsSync(destPath) || statSync(destPath).size !== file.size) {
      copyFileSync(file.fullPath, destPath);
      copied++;
    } else {
      // Same size — check content via hash
      const srcHash = hashFile(file.fullPath);
      const destHash = hashFile(destPath);
      if (srcHash !== destHash) {
        copyFileSync(file.fullPath, destPath);
        copied++;
      }
    }
    destSet.delete(file.path);
  }

  // Remove files that no longer exist in source
  for (const extra of destSet) {
    const extraPath = join(dest, extra);
    if (existsSync(extraPath)) {
      rmSync(extraPath);
    }
  }

  return copied;
}

/**
 * Sync source docs/assets to internal package copies
 */
function syncInternalCopies() {
  console.log('🔄 Syncing internal docs copies...\n');

  for (const destDir of INTERNAL_DOCS) {
    const label = relative(PROJECT_ROOT, destDir).replace(/\\/g, '/');
    const copied = mirrorDirectory(DOCS_SOURCE, destDir);
    console.log(`  ${label}: ${copied} files updated`);
  }

  // Sync assets too
  if (existsSync(ASSETS_SOURCE) && existsSync(INTERNAL_ASSETS)) {
    const label = relative(PROJECT_ROOT, INTERNAL_ASSETS).replace(/\\/g, '/');
    const copied = mirrorDirectory(ASSETS_SOURCE, INTERNAL_ASSETS);
    console.log(`  ${label}: ${copied} files updated`);
  }

  console.log('');
}

/**
 * Main build function
 */
function buildDocsBundle() {
  console.log('📦 YAKMESH Documentation Bundle Generator');
  console.log('=========================================\n');

  // Check if source exists
  if (!existsSync(DOCS_SOURCE)) {
    console.error(`❌ Documentation source not found: ${DOCS_SOURCE}`);
    process.exit(1);
  }

  // Sync source docs to internal package copies first
  syncInternalCopies();

  console.log(`📁 Source: ${DOCS_SOURCE}`);
  console.log(`📁 Assets: ${ASSETS_SOURCE}`);
  console.log(`📄 Output: ${BUNDLE_OUTPUT}\n`);

  // Collect files from docs and assets
  const docsFiles = collectFiles(DOCS_SOURCE, DOCS_SOURCE);
  const assetFiles = collectFiles(join(ASSETS_SOURCE, 'silhouettes'), join(ASSETS_SOURCE, 'silhouettes'), 'assets/silhouettes');

  const allFiles = [...docsFiles, ...assetFiles];

  console.log(`📊 Found ${docsFiles.length} documentation files`);
  console.log(`📊 Found ${assetFiles.length} asset files`);
  console.log(`📊 Total: ${allFiles.length} files\n`);

  // Build file index
  const fileIndex = {};
  const hashes = [];
  let totalSize = 0;

  console.log('🔐 Computing hashes...\n');

  for (const file of allFiles) {
    try {
      const hash = hashFile(file.fullPath);
      const contentType = getContentType(file.path);

      fileIndex[file.path] = {
        hash,
        size: file.size,
        contentType,
      };

      hashes.push(hash);
      totalSize += file.size;

      // Show progress for larger files or all HTML files
      const isImportant = file.path.endsWith('.html') || file.size > 10000;
      if (isImportant) {
        console.log(`  ✓ ${file.path} (${formatSize(file.size)})`);
      }
    } catch (err) {
      console.error(`  ✗ ${file.path}: ${err.message}`);
    }
  }

  // Compute bundle hash = SHA3-256(sorted individual hashes joined)
  hashes.sort();
  const joinedHashes = hashes.join('');
  const bundleHash = bytesToHex(sha3_256(new TextEncoder().encode(joinedHashes)));

  // Get version from package.json
  let version = '0.0.0';
  try {
    const pkg = JSON.parse(readFileSync(join(PROJECT_ROOT, 'package.json'), 'utf-8'));
    version = pkg.version;
  } catch { }

  const buildTime = new Date().toISOString();

  // Generate bundle.js content
  const bundleContent = `/**
 * YAKMESH Embedded Documentation Bundle
 * 
 * AUTO-GENERATED FILE - DO NOT EDIT MANUALLY
 * 
 * Regenerate with: npm run build:docs
 * Source: website/docs/
 * 
 * @generated ${buildTime}
 * @module embedded-docs/bundle
 */

/**
 * Master hash of the entire documentation bundle.
 * Computed as: SHA3-256(sorted individual file hashes joined)
 */
export const BUNDLE_HASH = '${bundleHash}';

/**
 * Version of the documentation bundle.
 * Matches the npm package version at build time.
 */
export const BUNDLE_VERSION = '${version}';

/**
 * Build timestamp (ISO 8601)
 */
export const BUNDLE_BUILT_AT = '${buildTime}';

/**
 * Index of all files in the documentation bundle.
 * 
 * Each entry contains:
 * - hash: SHA3-256 hash of the file content
 * - size: File size in bytes
 * - contentType: MIME type for HTTP serving
 * 
 * @type {Record<string, {hash: string, size: number, contentType: string}>}
 */
export const FILE_INDEX = ${JSON.stringify(fileIndex, null, 2)};

/**
 * Check if a file exists in the bundle
 * @param {string} path - File path relative to docs root
 * @returns {boolean}
 */
export function hasFile(path) {
  return path in FILE_INDEX;
}

/**
 * Get file metadata from the bundle
 * @param {string} path - File path relative to docs root
 * @returns {{hash: string, size: number, contentType: string} | null}
 */
export function getFileMeta(path) {
  return FILE_INDEX[path] || null;
}
`;

  // Write bundle
  writeFileSync(BUNDLE_OUTPUT, bundleContent, 'utf-8');

  // Summary
  const ioName = deriveNetworkName(bundleHash, 3);
  console.log('\n=========================================');
  console.log('✅ Bundle generated successfully!\n');
  console.log(`  📦 Bundle: ${ioName} (${bundleHash.substring(0, 8)}...)`);
  console.log(`  📋 Version: ${version}`);
  console.log(`  📁 Files: ${Object.keys(fileIndex).length}`);
  console.log(`  💾 Total Size: ${formatSize(totalSize)}`);
  console.log(`  🕐 Built: ${buildTime}`);
  console.log(`\n  Output: ${BUNDLE_OUTPUT}`);
  console.log('=========================================\n');

  return { bundleHash, version, fileCount: Object.keys(fileIndex).length, totalSize };
}

/**
 * Format bytes to human-readable size
 */
function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

// Run if called directly
buildDocsBundle();
