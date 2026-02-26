/**
 * YAKMESH Embedded Documentation Module
 * 
 * Self-contained, mathematically verified documentation that ships
 * with every YAKMESH node. No network required - docs are local.
 * 
 * @module embedded-docs
 * @author YAKMESH Team
 * @license MIT
 */

// Core exports
export { BUNDLE_HASH, BUNDLE_VERSION, FILE_INDEX } from './bundle.js';
export { verifyFile, verifyBundle, getBundleInfo } from './verify.js';
export { createDocsRouter, serveDocsFile, getDocsFile } from './serve.js';

// Re-export content types for convenience
export const DOCS_CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.json': 'application/json',
};

/**
 * Get content type for a file path
 * @param {string} path - File path
 * @returns {string} Content type
 */
export function getContentType(path) {
  const ext = path.substring(path.lastIndexOf('.'));
  return DOCS_CONTENT_TYPES[ext] || 'application/octet-stream';
}
