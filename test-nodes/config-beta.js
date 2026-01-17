/**
 * Node Beta Configuration
 * Part of 3-node test suite
 * Same codebase as Alpha (in Test 1), different ports
 */
export default {
  node: {
    name: 'Node Beta',
    region: 'local-test',
    capabilities: ['sync', 'validate', 'relay'],
  },
  
  network: {
    httpPort: 3002,
    wsPort: 9002,
    publicHost: 'localhost',
  },
  
  // Bootstrap to Alpha
  bootstrap: [
    'ws://localhost:9001',  // Alpha
  ],
  
  database: {
    path: './test-nodes/data-beta/yakmesh.db',
    contentPath: './test-nodes/data-beta/content',
    replication: {
      enabled: true,
      syncInterval: 5000,
    },
  },
  
  oracle: {
    minAttestations: 1,
  },
  
  security: {
    maxPeers: 10,
  },
};
