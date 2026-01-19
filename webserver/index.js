/**
 * Yakmesh Web Server Module
 * 
 * Manages an embedded Caddy web server for self-hosting websites
 * alongside the Yakmesh mesh network.
 * 
 * @module yakmesh/webserver
 */

import { spawn, execSync } from 'child_process';
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
      httpsPort: config.httpsPort || 8443,
      root: config.root || './htdocs',
      logPath: config.logPath || './logs',
      caddyPath: config.caddyPath || join(__dirname, 'bin'),
      autoHttps: config.autoHttps ?? false,
      domain: config.domain || null,
      phpEnabled: config.phpEnabled ?? false,
      phpPort: config.phpPort || 9000,
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
    
    execSync(`curl -L -o "${archivePath}" "${downloadUrl}"`, { stdio: 'inherit' });
    
    if (isWindows) {
      execSync(`powershell -Command "Expand-Archive -Path '${archivePath}' -DestinationPath '${this.config.caddyPath}' -Force"`, { stdio: 'inherit' });
    } else {
      execSync(`tar -xzf "${archivePath}" -C "${this.config.caddyPath}"`, { stdio: 'inherit' });
      execSync(`chmod +x "${this.caddyBinary}"`);
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
    
    if (this.config.domain && this.config.autoHttps) {
      return `# Yakmesh Web Server - ${this.config.domain}
${this.config.domain} {
    root * ${this.config.root}
    file_server
    ${phpBlock}
    
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
    }
}`;
    }
    
    return `# Yakmesh Web Server
{
    admin off
    auto_https off
}

:${this.config.port} {
    root * ${this.config.root}
    file_server
    ${phpBlock}
    
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

    log.info('Starting Yakmesh Web Server', { port: this.config.port });    this.process = spawn(this.caddyBinary, ['run', '--config', caddyfilePath], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false
    });
    
    this.process.stdout.on('data', (d) => log.debug('Caddy output', { message: d.toString().trim() }));
    this.process.stderr.on('data', (d) => log.error('Caddy error', { message: d.toString().trim() }));
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
