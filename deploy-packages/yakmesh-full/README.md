# YAKMESH Self-Contained Deployment Package
# Everything included - no external dependencies needed

## Quick Start

```powershell
.\start.ps1
```

That's it! Everything is bundled.

## What's Included

- ✅ Yakmesh mesh network core
- ✅ Content delivery API (public HTTP)
- ✅ Caddy 2.8.4 web server
- ✅ PHP 8.3 portable (FastCGI)
- ✅ Node.js 20 LTS portable
- ✅ 7-Zip CLI (archive handling)
- ✅ SQLite (embedded in Node)
- ✅ Pre-configured templates
- ✅ Demo website

## No External Dependencies

This package runs completely self-contained:
- No need to install Node.js globally
- No need to install PHP globally  
- No need for internet on startup
- Works in air-gapped environments

## Configuration

Edit `config/yakmesh.config.js` to customize:

```javascript
export default {
  name: 'My Node',
  port: 9001,
  httpPort: 3000,
  webPort: 8080,
  bootstrap: [],  // Add peer addresses here
  php: {
    enabled: true,  // PHP ready out of the box
    port: 9000,
  },
};
```

## Services

| URL | Service |
|-----|---------|
| http://localhost:9001 | Mesh P2P (WebSocket) |
| http://localhost:3000 | Content API |
| http://localhost:8080 | Web Server (PHP enabled) |

## Directory Structure

```
yakmesh-full/
├── bin/
│   ├── caddy.exe       # Caddy web server
│   ├── php/            # PHP 8.3 portable
│   │   ├── php-cgi.exe
│   │   └── php.ini
│   ├── node/           # Node.js 20 portable
│   │   └── node.exe
│   └── 7z/             # 7-Zip CLI
│       └── 7z.exe
├── config/
│   ├── yakmesh.config.js
│   ├── Caddyfile
│   └── php.ini
├── htdocs/
│   ├── index.html
│   ├── info.php        # PHP info page
│   └── api/            # API examples
├── data/
├── logs/
├── start.ps1
├── stop.ps1
└── README.md
```

## PHP Features

The bundled PHP includes common extensions:
- curl, openssl, mbstring
- json, sqlite3, pdo_sqlite
- gd, zip, zlib
- xml, dom, simplexml

## Archive Handling (7-Zip)

Use the bundled 7z for backup/restore:

```powershell
# Backup content
.\bin\7z\7z.exe a backup.7z data\content\*

# Restore content
.\bin\7z\7z.exe x backup.7z -odata\content\
```

## Platform Support

This package is built for **Windows x64**.

For other platforms, download platform-specific binaries:
- Linux: Use `yakmesh-full-linux-x64.tar.gz`
- macOS: Use `yakmesh-full-darwin-arm64.tar.gz`

## License

MIT License - see LICENSE file

Bundled software licenses:
- Caddy: Apache 2.0
- PHP: PHP License
- Node.js: MIT
- 7-Zip: LGPL
