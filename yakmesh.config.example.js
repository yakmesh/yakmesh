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
    httpPort: 3080,
    wsPort: 9080,
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


