/**
 * Node Alpha Configuration
 * Part of 3-node test suite
 * Same codebase as Beta (in Test 1), different ports
 */
export default {
  node: {
    name: 'Node Alpha',
    region: 'local-test',
    capabilities: ['sync', 'validate', 'relay'],
  },
  
  network: {
    httpPort: 3001,
    wsPort: 9001,
    publicHost: 'localhost',
  },
  
  // Bootstrap to Beta for mesh formation
  bootstrap: [
    'ws://localhost:9002',  // Beta
  ],
  
  database: {
    path: './test-nodes/data-alpha/yakmesh.db',
    contentPath: './test-nodes/data-alpha/content',
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
