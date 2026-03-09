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
