// YAKMESH Production Node Configuration
// Hostinger VPS
export default {
  nodeId: 'yakmesh-hostinger',
  
  // Content API server
  server: { 
    port: 3080, 
    host: '0.0.0.0' 
  },
  
  // Mesh P2P networking
  mesh: { 
    port: 9080, 
    host: '0.0.0.0' 
  },
  
  // Peer nodes to connect to
  peers: [
    // Add Hostinger production node once deployed
    // 'wss://peerquanta.com:9001'
  ],
  
  // Data storage
  dataDir: './data',
  
  // Oracle settings
  oracle: {
    timeSource: 'auto',
    phaseWindow: 30000
  },
  
  // Enable ANNEX encrypted P2P
  annex: {
    enabled: true
  }
};
