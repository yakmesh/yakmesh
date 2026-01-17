# YAKMESH Deployment Packages

Two deployment variants for different use cases:

## 📦 Package Variants

### `yakmesh-minimal/` - Minimal Package
**Best for:** Advanced users, custom setups, cloud deployments

Includes:
- Yakmesh core (mesh network + content API)
- Caddy web server (auto-downloads on first run)
- Basic startup scripts

**You provide:** PHP runtime, Node.js (if needed), custom configurations

Size: ~3 MB (compressed)

### `yakmesh-full/` - Self-Contained Package  
**Best for:** Turnkey deployments, air-gapped environments, quick demos

Includes everything in minimal, PLUS:
- PHP 8.3 portable (FastCGI ready)
- Node.js 20 LTS portable
- 7-Zip CLI (archive handling)
- Pre-configured Caddyfile templates
- Sample htdocs with demo site

Size: ~100 MB (compressed)

## Quick Start

### Minimal Package
```powershell
cd yakmesh-minimal
.\start.ps1
# First run downloads Caddy automatically
```

### Full Package  
```powershell
cd yakmesh-full
.\start.ps1
# Everything included - no downloads needed
```

## Directory Structure

```
yakmesh-{variant}/
├── bin/                    # Executables (Caddy, PHP, Node, 7z)
│   ├── caddy.exe          # Web server (auto-downloaded in minimal)
│   ├── php/               # PHP portable (full only)
│   ├── node/              # Node.js portable (full only)
│   └── 7z/                # 7-Zip CLI (full only)
├── config/
│   ├── yakmesh.config.js  # Main configuration
│   ├── Caddyfile          # Web server config
│   └── php.ini            # PHP config (full only)
├── htdocs/                # Web document root
│   └── index.html         # Demo page
├── data/                  # Persistent data
│   ├── content/           # Content store
│   └── database/          # SQLite databases
├── logs/                  # Log files
├── start.ps1              # Windows startup
├── start.sh               # Linux/Mac startup
├── stop.ps1               # Windows shutdown
└── README.md              # Usage instructions
```

## Configuration

### yakmesh.config.js
```javascript
export default {
  // Node identity
  name: 'My Yakmesh Node',
  
  // Network
  port: 9001,           // Mesh port
  httpPort: 3000,       // Content API
  webPort: 8080,        // Caddy web server
  
  // Bootstrap peers (leave empty for standalone)
  bootstrap: [],
  
  // PHP settings (full package only)
  php: {
    enabled: true,
    port: 9000,
  },
  
  // Content delivery
  content: {
    root: './htdocs',
    cacheMaxAge: 86400,
  }
};
```

## Port Reference

| Service | Port | Description |
|---------|------|-------------|
| Mesh | 9001 | P2P WebSocket connections |
| Content API | 3000 | Public content delivery |
| Web Server | 8080 | Caddy (HTTP) |
| Web Server HTTPS | 8443 | Caddy (HTTPS, if configured) |
| PHP FastCGI | 9000 | PHP-FPM (full package) |

## License

MIT License - see LICENSE file
