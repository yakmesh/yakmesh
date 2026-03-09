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
 * Yakmesh Node Configuration Example
 * Copy this to yakmesh.config.js and customize for your deployment
 */
export default {
  // Node identity
  node: {
    name: 'My Yakmesh Node',
    region: 'us-east',
    capabilities: ['sync', 'validate', 'relay'],
  },
  
  // Network settings
  network: {
    httpPort: 3000,
    wsPort: 9001,
    publicHost: 'localhost',
    // Custom identity salt - creates a unique network
    // Different salts = different networks (cannot interoperate)
    identityConfig: {
      networkPrefix: 'my',  // e.g., my-abc123
      identitySalt: 'my-app-network-v1',
    },
  },
  
  // Bootstrap nodes (entry points to join existing mesh)
  bootstrap: [
    // 'wss://Yakmesh1.example.com:9001',
    // 'wss://Yakmesh2.example.com:9001',
  ],
  
  // Database configuration
  database: {
    path: './data/yakmesh.db',
    replication: {
      enabled: true,
      syncInterval: 30000,  // 30 seconds
    },
  },
  
  // Adapter configuration (optional)
  // Adapters bridge external data sources with the mesh
  adapter: {
    enabled: false,
    // type: 'sqlite',  // or 'postgres', 'rest', 'custom'
    // config: { ... adapter-specific config ... }
  },
  
  // Oracle settings
  oracle: {
    minAttestations: 1,  // Minimum attestations for consensus
  },
  
  // Security settings
  security: {
    maxPeers: 50,
    requireAuth: false,  // Enable for private networks
  },
};


