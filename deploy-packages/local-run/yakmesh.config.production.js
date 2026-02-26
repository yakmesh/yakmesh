// Yakmesh Production Configuration Reference
// ----------------------------------------------------------
// Not loaded at runtime (start.sh uses yakmesh.config.js).
// Kept for reference. This file IS oracle-hashed, so it must
// be byte-identical across all deployments.
// ----------------------------------------------------------
export default {
  node: {
    name: 'Yakmesh Node',
    region: 'production',
  },
  network: {
    httpPort: 3080,
    wsPort: 9080,
  },
  bootstrap: [
    'ws://156.67.75.34:9080',   // Hostinger VPS
  ],
  database: {
    path: './data/yakmesh.db',
    replication: { enabled: true, syncInterval: 5000 },
  },
  oracle: { timeSource: 'auto', phaseWindow: 30000 },
  annex: { enabled: true },
};
