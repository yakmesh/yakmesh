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
 * YAKMESH Embedded Documentation Module
 * 
 * Self-contained, mathematically verified documentation that ships
 * with every YAKMESH node. No network required - docs are local.
 * 
 * @module embedded-docs
 * @author YAKMESH Team
 * @license YakMesh-NE-1.0 (YAKMESH NETWORK ENGINE LICENSE AGREEMENT v1.0)
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
