#!/usr/bin/env node
/**
 * YAK:// Protocol Handler Executable
 * This script is invoked by the OS when a yak:// URL is clicked.
 * Self-contained CommonJS - no ES module imports for compatibility.
 */

const { exec } = require('child_process');
const { platform } = require('os');
const { readFileSync } = require('fs');
const { join } = require('path');

// Read port from canonical config — single source of truth
// Override via YAKMESH_HTTP_PORT env var for multi-node setups
let PORT = 3080;
try {
  const portsJson = JSON.parse(readFileSync(join(__dirname, '..', 'config', 'ports.json'), 'utf8'));
  PORT = parseInt(process.env.YAKMESH_HTTP_PORT, 10) || portsJson.httpPort || 3080;
} catch { PORT = parseInt(process.env.YAKMESH_HTTP_PORT, 10) || 3080; }

// Built-in routes that map to HTTP endpoints
const BUILTIN_ROUTES = {
  'dashboard': '/dashboard/',
  'docs': '/docs/',
  'docs.yakmesh': '/docs/',
  'site': '/site/',
  'content': '/content/',
  'node': '/node',
  'peers': '/peers',
  'metrics': '/metrics',
  'health': '/health',
  'gossip': '/gossip',
  'discovered': '/discovered',
  'domains': '/domains',
  'websites': '/websites',
  'security': '/security/status',
  'namche': '/security/namche/gates',
  'doko': '/security/doko/stats',
  'oracle': '/oracle/status',
  'time': '/time/status',
  'bookmarks': '/bookmarks'
};

/**
 * Convert yak:// URL to HTTP URL
 */
function yakToHttp(yakUrl, port) {
  const match = yakUrl.match(/^(y|yak):\/\/(.+)$/i);
  if (!match) return `http://localhost:${port}/dashboard/`;

  const path = match[2];
  const parts = path.split('/').filter(Boolean);
  const host = parts[0].toLowerCase();
  const subPath = parts.length > 1 ? '/' + parts.slice(1).join('/') : '';

  // Check builtin routes
  if (BUILTIN_ROUTES[host]) {
    return `http://localhost:${port}${BUILTIN_ROUTES[host]}${subPath}`;
  }

  // Check content hash (64 char hex)
  if (/^[a-f0-9]{64}$/i.test(host)) {
    return `http://localhost:${port}/content/${host}`;
  }

  // Content with explicit prefix
  if (host === 'content' && parts.length > 1) {
    return `http://localhost:${port}/content/${parts[1]}`;
  }

  // Unknown - 404
  return `http://localhost:${port}/404?url=${encodeURIComponent(yakUrl)}`;
}

// Get the URL from command line arguments
const url = process.argv[2];

if (!url || !url.match(/^(y|yak):\/\//i)) {
  console.error('Usage: yak-handler.cjs yak://...');
  process.exit(1);
}

// Convert to HTTP URL
const httpUrl = yakToHttp(url, PORT);

console.log(`🦬 YAK Protocol: ${url}`);
console.log(`   → ${httpUrl}`);

// Open in default browser
const os = platform();
let cmd;

switch (os) {
  case 'win32':
    cmd = `start "" "${httpUrl}"`;
    break;
  case 'darwin':
    cmd = `open "${httpUrl}"`;
    break;
  default:
    cmd = `xdg-open "${httpUrl}"`;
}

exec(cmd, (error) => {
  if (error) {
    console.error('Failed to open browser:', error.message);
    process.exit(1);
  }
});
