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
