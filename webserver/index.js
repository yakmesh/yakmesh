/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * Yakmesh Web Server Module
 * 
 * Manages an embedded Caddy web server for self-hosting websites
 * alongside the Yakmesh mesh network.
 * 
 * @module yakmesh/webserver
 */

import { spawn, execSync, execFileSync } from 'child_process';
import { existsSync, writeFileSync, mkdirSync, unlinkSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createLogger } from '../utils/logger.js';

const log = createLogger('webserver:main');

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Caddy download URLs by platform
 */
const CADDY_DOWNLOADS = {
  'win32-x64': 'https://github.com/caddyserver/caddy/releases/download/v2.8.4/caddy_2.8.4_windows_amd64.zip',
  'win32-arm64': 'https://github.com/caddyserver/caddy/releases/download/v2.8.4/caddy_2.8.4_windows_arm64.zip',
  'linux-x64': 'https://github.com/caddyserver/caddy/releases/download/v2.8.4/caddy_2.8.4_linux_amd64.tar.gz',
  'linux-arm64': 'https://github.com/caddyserver/caddy/releases/download/v2.8.4/caddy_2.8.4_linux_arm64.tar.gz',
  'darwin-x64': 'https://github.com/caddyserver/caddy/releases/download/v2.8.4/caddy_2.8.4_mac_amd64.tar.gz',
  'darwin-arm64': 'https://github.com/caddyserver/caddy/releases/download/v2.8.4/caddy_2.8.4_mac_arm64.tar.gz',
};

/**
 * Yakmesh Web Server - Embedded Caddy for self-hosting
 */
export class YakmeshWebServer {
  constructor(config = {}) {
    this.config = {
      port: config.port || 8080,
      httpsPort: config.httpsPort || 443,
      root: config.root || './public',
      logPath: config.logPath || './logs',
      caddyPath: config.caddyPath || join(__dirname, 'bin'),
      autoHttps: config.autoHttps ?? false,
      domain: config.domain || null,
      phpEnabled: config.phpEnabled ?? false,
      phpPort: config.phpPort || 9000,
      // Yakmesh node proxy settings
      nodeProxy: config.nodeProxy ?? true,
      nodeHttpPort: config.nodeHttpPort || 3080,
      nodeWsPort: config.nodeWsPort || 9080,
      acmeEmail: config.acmeEmail || null,
      ...config
    };

    this.process = null;
    this.running = false;
    this.caddyBinary = this._getCaddyBinaryPath();
  }

  _getCaddyBinaryPath() {
    const ext = process.platform === 'win32' ? '.exe' : '';
    return join(this.config.caddyPath, `caddy${ext}`);
  }

  _getPlatformKey() {
    return `${process.platform}-${process.arch}`;
  }

  isInstalled() {
    return existsSync(this.caddyBinary);
  }

  async install() {
    const platformKey = this._getPlatformKey();
    const downloadUrl = CADDY_DOWNLOADS[platformKey];

    if (!downloadUrl) {
      throw new Error(`Unsupported platform: ${platformKey}`);
    }

    log.info('Downloading Caddy', { platform: platformKey });
    mkdirSync(this.config.caddyPath, { recursive: true });

    const isWindows = process.platform === 'win32';
    const archiveExt = isWindows ? 'zip' : 'tar.gz';
    const archivePath = join(this.config.caddyPath, `caddy.${archiveExt}`);

    // SECURITY: Use execFileSync to prevent shell injection via paths/URLs
    execFileSync('curl', ['-L', '-o', archivePath, downloadUrl], { stdio: 'inherit' });

    if (isWindows) {
      execFileSync('powershell', ['-Command', `Expand-Archive -Path '${archivePath}' -DestinationPath '${this.config.caddyPath}' -Force`], { stdio: 'inherit' });
    } else {
      execFileSync('tar', ['-xzf', archivePath, '-C', this.config.caddyPath], { stdio: 'inherit' });
      execFileSync('chmod', ['+x', this.caddyBinary]);
    }

    unlinkSync(archivePath);
    log.info('Caddy installed successfully');
    return true;
  }

  generateCaddyfile() {
    const phpBlock = this.config.phpEnabled ? `
    @phpFiles path *.php
    handle @phpFiles {
        reverse_proxy localhost:${this.config.phpPort}
    }` : '';

    // Yakmesh node reverse proxy with WebSocket support
    const nodeProxyBlock = this.config.nodeProxy ? `
    # Yakmesh mesh WebSocket endpoint (priority)
    @meshWs {
        path /mesh/ws
        header Connection *Upgrade*
        header Upgrade websocket
    }
    handle @meshWs {
        reverse_proxy localhost:${this.config.nodeWsPort}
    }
    
    # Yakmesh mesh HTTP endpoints
    @meshHttp {
        path /mesh/*
        path /health
        path /beacon
        path /.well-known/yakmesh/*
        path /api/*
        path /komm/*
        path /darshan/*
        path /rumors
        path /gossip/*
        path /dashboard
        path /dashboard/*
        path /docs
        path /docs/*
    }
    handle @meshHttp {
        reverse_proxy localhost:${this.config.nodeHttpPort}
    }
    
    # KOMM WebSocket
    @kommWs {
        path /komm/ws
        header Connection *Upgrade*
        header Upgrade websocket
    }
    handle @kommWs {
        reverse_proxy localhost:${this.config.nodeHttpPort}
    }` : '';

    if (this.config.domain && this.config.autoHttps) {
      const acmeBlock = this.config.acmeEmail ? `
{
    email ${this.config.acmeEmail}
}
` : '';
      return `# Yakmesh Web Server - ${this.config.domain}
# Auto-HTTPS via Let's Encrypt
${acmeBlock}
${this.config.domain} {
    ${nodeProxyBlock}
    ${phpBlock}
    
    # Static files fallback
    root * ${this.config.root}
    file_server
    
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
    }
    
    log {
        output file ${this.config.logPath}/access.log
        format json
    }
}`;
    }

    // Local/dev mode without HTTPS
    return `# Yakmesh Web Server (Local Mode)
{
    admin off
    auto_https off
}

:${this.config.port} {
    ${nodeProxyBlock}
    ${phpBlock}
    
    # Static files fallback
    root * ${this.config.root}
    file_server
    
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
    }
}`;
  }

  writeCaddyfile(content = null) {
    const caddyfilePath = join(this.config.caddyPath, 'Caddyfile');
    mkdirSync(dirname(caddyfilePath), { recursive: true });
    writeFileSync(caddyfilePath, content || this.generateCaddyfile(), 'utf8');
    return caddyfilePath;
  }

  async start() {
    if (this.running) {
      log.warn('Web server already running');
      return;
    }

    if (!this.isInstalled()) {
      log.info('Caddy not found, installing...');
      await this.install();
    }

    mkdirSync(this.config.root, { recursive: true });
    mkdirSync(this.config.logPath, { recursive: true });

    const caddyfilePath = this.writeCaddyfile();

    log.info('Starting Yakmesh Web Server', { port: this.config.port }); this.process = spawn(this.caddyBinary, ['run', '--config', caddyfilePath], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false
    });

    this.process.stdout.on('data', (d) => log.debug('Caddy output', { message: d.toString().trim() }));

    // Caddy writes JSON logs to stderr - parse level and route appropriately
    this.process.stderr.on('data', (d) => {
      const msg = d.toString().trim();
      // Each line may be a separate JSON log entry
      for (const line of msg.split('\n')) {
        try {
          const parsed = JSON.parse(line);
          const level = parsed.level || 'info';
          const logMsg = parsed.msg || line;
          if (level === 'error' || level === 'fatal') {
            log.error('Caddy', { level, msg: logMsg });
          } else if (level === 'warn') {
            log.warn('Caddy', { level, msg: logMsg });
          } else {
            log.debug('Caddy', { level, msg: logMsg });
          }
        } catch {
          // Not JSON - log as debug (probably startup banner)
          log.debug('Caddy', { message: line });
        }
      }
    });

    this.process.on('close', (code) => { this.running = false; });

    this.running = true;
    await new Promise(r => setTimeout(r, 1000));

    log.info('Web server running', { url: `http://localhost:${this.config.port}`, root: this.config.root });
    return this;
  }

  async stop() {
    if (!this.running || !this.process) return;
    log.info('Stopping web server');

    return new Promise((resolve) => {
      this.process.on('close', () => {
        this.running = false;
        this.process = null;
        resolve();
      });

      if (process.platform === 'win32') {
        spawn('taskkill', ['/pid', this.process.pid, '/f', '/t']);
      } else {
        this.process.kill('SIGTERM');
      }
    });
  }

  status() {
    return {
      running: this.running,
      port: this.config.port,
      root: this.config.root,
      caddyInstalled: this.isInstalled(),
      pid: this.process?.pid || null
    };
  }
}

export async function startWebServer(options = {}) {
  const server = new YakmeshWebServer(options);
  await server.start();
  return server;
}

export default YakmeshWebServer;
