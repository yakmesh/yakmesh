# YAKMESH Basic Deployment Package

**Best for:** Shared hosting (Hostinger, cPanel), VPS with Node.js, cloud deployments

This is a lightweight Node.js-only deployment designed for webhosts that provide Node.js runtime.

## Contents

```
yakmesh-basic/
├── server/           # Express server
├── mesh/             # P2P mesh networking
├── gossip/           # Gossip protocol
├── oracle/           # Network oracle
├── identity/         # Node identity (ML-DSA-65)
├── content/          # Content management
├── database/         # SQLite adapter
├── utils/            # Utilities
├── adapters/         # PeerQuanta adapters
├── security/         # Rate limiting, validation
├── data/             # Runtime data (created on start)
├── package.json      # Dependencies
├── ecosystem.config.json  # PM2 configuration
├── yakmesh.config.js      # Node configuration
└── README.md         # This file
```

## Quick Start (Hostinger)

### 1. Upload files
Upload this entire folder to your Hostinger account via SFTP or Git.

### 2. SSH and install
```bash
ssh -p 65002 your_user@your_host
cd ~/yakmesh-basic
npm install --production
```

### 3. Start with PM2
```bash
pm2 start ecosystem.config.json
pm2 save
```

### 4. Verify
```bash
curl http://localhost:3000/health
curl http://localhost:3000/.well-known/yakmesh/beacon
```

## Configuration

Edit `yakmesh.config.js`:

```javascript
export default {
  port: 3000,           // HTTP API port
  wsPort: 9001,         // WebSocket mesh port
  bootstrap: [          // Peer nodes to connect to
    'ws://peer1.example.com:9001',
    'ws://peer2.example.com:9001'
  ]
};
```

## PM2 Commands

```bash
pm2 start yakmesh      # Start
pm2 stop yakmesh       # Stop
pm2 restart yakmesh    # Restart
pm2 logs yakmesh       # View logs
pm2 monit              # Monitor
```

## Ports

| Port | Service | Description |
|------|---------|-------------|
| 3000 | HTTP API | Content, health, dashboard |
| 9001 | WebSocket | Mesh peer connections |

## Requirements

- Node.js 18+ (LTS recommended)
- npm or yarn
- PM2 (optional, for production)

## License

MIT License - see LICENSE file
