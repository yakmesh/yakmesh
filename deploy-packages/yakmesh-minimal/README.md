# YAKMESH Minimal Deployment Package
# Lightweight - downloads dependencies on first run

## Quick Start

```powershell
.\start.ps1
```

## What's Included

- ✅ Yakmesh mesh network core
- ✅ Content delivery API (public HTTP)
- ✅ Caddy web server (auto-downloads)
- ✅ Startup/shutdown scripts

## What You Need

- Node.js 18+ (must be in PATH)
- Internet connection (for first-time Caddy download)
- (Optional) PHP 8+ if you want PHP support

## Configuration

Edit `config/yakmesh.config.js` to customize:

```javascript
export default {
  name: 'My Node',
  port: 9001,
  httpPort: 3000,
  webPort: 8080,
  bootstrap: [],  // Add peer addresses here
};
```

## Adding PHP Support

1. Install PHP and ensure `php-cgi` is in PATH
2. Edit config:
   ```javascript
   php: {
     enabled: true,
     port: 9000,
   }
   ```
3. Restart the node

## Services

| URL | Service |
|-----|---------|
| http://localhost:9001 | Mesh P2P (WebSocket) |
| http://localhost:3000 | Content API |
| http://localhost:8080 | Web Server (Caddy) |

## Directory Structure

```
yakmesh-minimal/
├── bin/              # Caddy downloads here
├── config/           # Configuration files
├── htdocs/           # Your website files
├── data/             # Persistent data
├── logs/             # Log files
├── start.ps1         # Start everything
├── stop.ps1          # Stop everything
└── README.md         # This file
```
