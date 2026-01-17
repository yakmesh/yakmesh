/**
 * YAKMESH Minimal Configuration
 * Edit this file to customize your node
 */

export default {
  // ========================================
  // NODE IDENTITY
  // ========================================
  name: 'Yakmesh Node',
  
  // ========================================
  // NETWORK PORTS
  // ========================================
  port: 9001,           // Mesh P2P WebSocket
  httpPort: 3000,       // Content API (public HTTP)
  webPort: 8080,        // Caddy web server
  
  // ========================================
  // BOOTSTRAP PEERS
  // ========================================
  // Add peer addresses to join an existing network
  // Leave empty to start a standalone node
  bootstrap: [
    // 'ws://peer1.example.com:9001',
    // 'ws://192.168.1.100:9001',
  ],
  
  // ========================================
  // WEB SERVER (CADDY)
  // ========================================
  web: {
    enabled: true,
    port: 8080,
    root: './htdocs',
    autoHttps: false,      // Enable for production with domain
    domain: null,          // e.g., 'mysite.example.com'
  },
  
  // ========================================
  // PHP SUPPORT (Optional)
  // ========================================
  // Requires php-cgi in PATH (minimal package)
  php: {
    enabled: false,
    port: 9000,
    // binary: 'php-cgi',  // Custom path if needed
  },
  
  // ========================================
  // CONTENT DELIVERY
  // ========================================
  content: {
    enabled: true,
    storagePath: './data/content',
    maxSize: 100 * 1024 * 1024,  // 100 MB per item
    cacheMaxAge: 86400,          // 24 hours
  },
  
  // ========================================
  // SECURITY
  // ========================================
  security: {
    enableCodeProof: true,       // Verify peer code integrity
    rateLimit: {
      windowMs: 60000,           // 1 minute
      maxRequests: 100,          // Per IP
    },
  },
  
  // ========================================
  // LOGGING
  // ========================================
  logging: {
    level: 'info',               // debug, info, warn, error
    path: './logs',
    maxFiles: 7,                 // Days to keep
  },
};
