/**
 * YAKMESH Documentation Serving
 * 
 * Serve hardcoded documentation via HTTP or yak:// protocol.
 * Zero network latency - docs are served from local storage.
 * 
 * @module embedded-docs/serve
 */

import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { FILE_INDEX, BUNDLE_HASH, BUNDLE_VERSION, hasFile, getFileMeta } from './bundle.js';
import { getContentType } from './index.js';

// Calculate docs directory relative to this module
const __dirname = dirname(fileURLToPath(import.meta.url));

// Documentation location:
// In development: ../website/docs (sibling to yakmesh-node)
// In production (npm package): ./website/docs (included in package)
const DOCS_DIR = existsSync(join(__dirname, '../../website/docs'))
  ? join(__dirname, '../../website/docs')     // Development: sibling folder
  : join(__dirname, '../website/docs');       // Production: in package

const ASSETS_DIR = existsSync(join(__dirname, '../../website/assets'))
  ? join(__dirname, '../../website/assets')   // Development
  : join(__dirname, '../website/assets');     // Production

/**
 * Get a documentation file by path
 * 
 * @param {string} path - File path relative to docs root (e.g., 'index.html', 'mandala.html')
 * @returns {{content: Buffer, meta: {hash: string, size: number, contentType: string}} | null}
 */
export function getDocsFile(path) {
  // Normalize path - remove leading slash if present
  const normalizedPath = path.startsWith('/') ? path.substring(1) : path;
  
  // Check if file is in bundle
  const meta = getFileMeta(normalizedPath);
  
  // Try to read from disk
  // First try docs directory, then assets for silhouettes etc.
  let fullPath = join(DOCS_DIR, normalizedPath);
  
  if (!existsSync(fullPath)) {
    // Try assets directory (for silhouettes, etc.)
    fullPath = join(ASSETS_DIR, normalizedPath.replace('assets/', ''));
  }
  
  if (!existsSync(fullPath)) {
    return null;
  }
  
  try {
    const content = readFileSync(fullPath);
    
    return {
      content,
      meta: meta || {
        hash: 'unverified',
        size: content.length,
        contentType: getContentType(normalizedPath)
      }
    };
  } catch (err) {
    console.error(`[embedded-docs] Error reading ${normalizedPath}:`, err.message);
    return null;
  }
}

/**
 * Serve a documentation file (for use with HTTP response)
 * 
 * @param {string} path - File path to serve
 * @param {object} res - Express/HTTP response object
 */
export function serveDocsFile(path, res) {
  const file = getDocsFile(path);
  
  if (!file) {
    res.status(404).json({
      error: 'Documentation file not found',
      path,
      available: listDocsFiles().filter(f => f.endsWith('.html'))
    });
    return;
  }
  
  // Set headers for immutable content
  res.setHeader('Content-Type', file.meta.contentType);
  res.setHeader('Content-Length', file.content.length);
  res.setHeader('X-Content-Hash', file.meta.hash);
  res.setHeader('X-Bundle-Hash', BUNDLE_HASH);
  res.setHeader('X-Bundle-Version', BUNDLE_VERSION);
  
  // Immutable caching - content is verified by hash
  res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
  res.setHeader('ETag', `"${file.meta.hash}"`);
  
  res.send(file.content);
}

/**
 * List all documentation files
 * 
 * @returns {string[]} Array of file paths
 */
export function listDocsFiles() {
  return Object.keys(FILE_INDEX);
}

/**
 * Create Express router for /docs/ endpoint
 * 
 * @returns {Promise<object>} Express Router (async to allow dynamic import)
 */
export async function createDocsRouter() {
  // Dynamic import to avoid requiring express if not used
  let Router;
  try {
    const express = await import('express');
    Router = express.Router;
  } catch {
    // Fallback for environments without express
    console.warn('[embedded-docs] Express not available, createDocsRouter disabled');
    return null;
  }
  
  const router = Router();
  
  // Documentation index
  router.get('/', (req, res) => {
    res.redirect('/docs/index.html');
  });
  
  // Serve any documentation file
  router.get('/:file(*)', (req, res) => {
    const file = req.params.file || 'index.html';
    serveDocsFile(file, res);
  });
  
  // Bundle info endpoint (for verification)
  router.get('/_bundle', (req, res) => {
    res.json({
      hash: BUNDLE_HASH,
      version: BUNDLE_VERSION,
      fileCount: Object.keys(FILE_INDEX).length,
      files: FILE_INDEX
    });
  });
  
  return router;
}

/**
 * Handle yak://docs.yakmesh/ requests
 * 
 * @param {string} yakPath - Path from yak:// URL (e.g., '/mandala' -> 'mandala.html')
 * @returns {{content: Buffer, meta: object} | null}
 */
export function handleYakDocsRequest(yakPath) {
  // Remove leading slash
  let path = yakPath.startsWith('/') ? yakPath.substring(1) : yakPath;
  
  // Handle root request
  if (!path || path === '') {
    path = 'index.html';
  }
  
  // Add .html extension if not present for convenience
  if (!path.includes('.')) {
    path += '.html';
  }
  
  return getDocsFile(path);
}
