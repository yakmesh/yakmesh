/**
 * YAKMESH Self-Contained Configuration
 * Full package with all features enabled
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
  bootstrap: [
    // 'ws://peer1.example.com:9001',
    // 'ws://192.168.1.100:9001',
  ],
  
  // ========================================
  // WEB SERVER (CADDY) - Pre-configured
  // ========================================
  web: {
    enabled: true,
    port: 8080,
    httpsPort: 8443,
    root: './htdocs',
    autoHttps: false,
    domain: null,
  },
  
  // ========================================
  // PHP SUPPORT - Bundled & Ready
  // ========================================
  php: {
    enabled: true,
    port: 9000,
    binary: './bin/php/php-cgi.exe',
    ini: './bin/php/php.ini',
    extensions: [
      'curl', 'openssl', 'mbstring',
      'json', 'sqlite3', 'pdo_sqlite',
      'gd', 'zip', 'zlib',
      'xml', 'dom', 'simplexml',
    ],
  },
  
  // ========================================
  // NODE.JS - Bundled Runtime
  // ========================================
  node: {
    binary: './bin/node/node.exe',
    version: '20.x LTS',
  },
  
  // ========================================
  // ARCHIVE HANDLING (7-Zip)
  // ========================================
  archive: {
    binary: './bin/7z/7z.exe',
    formats: ['7z', 'zip', 'tar', 'gz'],
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
    enableCodeProof: true,
    rateLimit: {
      windowMs: 60000,
      maxRequests: 100,
    },
  },
  
  // ========================================
  // LOGGING
  // ========================================
  logging: {
    level: 'info',
    path: './logs',
    maxFiles: 7,
  },
};
