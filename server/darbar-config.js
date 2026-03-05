/**
 * DARBAR config for yakmesh-node
 *
 * Wires DARBAR auth levels to yakmesh-node's identity & peer subsystems.
 * Must be initialized with a YakmeshNode instance (class methods required).
 *
 * yakmesh-node uses:
 *   - `public`  — open GET status endpoints
 *   - `local`   — localhost-only operations (sign, identity backup, SSE)
 *   - `peer`    — ML-DSA-65 signed headers (requirePeerAuth equivalent)
 *
 * `user`, `admin`, and `host` auth levels are NOT used in yakmesh-node
 * (no JWT, no game accounts). They are available but will reject with
 * "not configured" errors.
 *
 * Usage:
 *   import { createYakmeshDarbarConfig } from './darbar-config.js';
 *   const darbar = createDarbar(createYakmeshDarbarConfig(this));
 *
 * @module darbar-config
 */

import { verifySignature } from '../identity/node-key.js';

/**
 * Create a DARBAR config wired to a YakmeshNode instance.
 *
 * @param {import('./index.js').YakmeshNode} node  Active node instance
 * @returns {import('./darbar.js').DarbarConfig}
 */
export function createYakmeshDarbarConfig(node) {
  return {
    // No JWT auth in yakmesh-node — peer mesh only
    verifyToken: null,
    resolveIdentity: null,

    // Host persistentId = this node's own persistentId
    hostPersistentId: () => node.identity?.getPersistentId?.() || null,

    // No delegate system in yakmesh-node (P2P mesh, no admin hierarchy)
    isDelegate: null,

    // Peer auth: resolve public key from mesh peer registry
    resolvePeerKey: (nodeId) => node._resolvePeerPublicKey(nodeId),

    // ML-DSA-65 signature verification
    verifySignature: (message, signature, publicKey) => {
      return verifySignature(message, signature, publicKey);
    },

    // Use the node's logger
    log: node.log || console,
  };
}

export default createYakmeshDarbarConfig;
