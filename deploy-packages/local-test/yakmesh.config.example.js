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


