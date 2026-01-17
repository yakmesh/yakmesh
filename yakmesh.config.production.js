// YAKMESH Production Node Configuration
// LAN Server: WIN-LQH9ULSNBFU (Abyss)
export default {
  nodeId: 'yakmesh-abyss',
  
  // Content API server
  server: { 
    port: 3000, 
    host: '0.0.0.0' 
  },
  
  // Mesh P2P networking
  mesh: { 
    port: 9001, 
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
