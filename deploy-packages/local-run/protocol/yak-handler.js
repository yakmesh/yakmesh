#!/usr/bin/env node
/**
 * Y:// Protocol Handler Executable
 * This script is invoked by the OS when a y:// URL is clicked.
 * 
 * SECURITY: Uses execFile (no shell) to prevent command injection.
 * The URL is validated to only produce http://localhost:PORT/... URLs.
 * 
 * Self-contained - no ES module imports for compatibility.
 */

const { execFile } = require('child_process');
const { platform } = require('os');

const PORT = 3000;

// Built-in routes that map to HTTP endpoints
const BUILTIN_ROUTES = {
  'dashboard': '/dashboard/',
  'site': '/site/',
  'content': '/content',
  'node': '/node',
  'peers': '/peers',
  'metrics': '/metrics',
  'health': '/health',
  'gossip': '/gossip',
  'discovered': '/discovered',
  'domains': '/domains',
  'security': '/security',
  'namche': '/namche/',
  'doko': '/doko/',
  'oracle': '/oracle',
  'time': '/time'
};

/**
 * Convert y:// URL to HTTP URL
 */
function yakToHttp(yakUrl, port = PORT) {
  // Parse URL
  const match = yakUrl.match(/^(y|yak):\/\/(.+)$/i);
  if (!match) {
    return `http://localhost:${port}/`;
  }
  
  const path = match[2];
  
  // Split path and query/fragment
  const [routePart, ...rest] = path.split(/[?#]/);
  const suffix = rest.length > 0 ? '?' + rest.join('') : '';
  
  // Check builtin routes
  const routeKey = routePart.split('/')[0].toLowerCase();
  if (BUILTIN_ROUTES[routeKey]) {
    const subPath = routePart.substring(routeKey.length);
    return `http://localhost:${port}${BUILTIN_ROUTES[routeKey]}${subPath}${suffix}`;
  }
  
  // Check .yak domain
  if (routePart.endsWith('.yak') || routePart.includes('.yak/')) {
    return `http://localhost:${port}/yak/${routePart}${suffix}`;
  }
  
  // Check content hash (64 char hex)
  if (/^[a-f0-9]{64}/i.test(routePart)) {
    return `http://localhost:${port}/content/${routePart}${suffix}`;
  }
  
  // Default: treat as path
  return `http://localhost:${port}/${routePart}${suffix}`;
}

// Get the URL from command line arguments
const url = process.argv[2];

if (!url || !url.match(/^(y|yak):\/\//i)) {
  console.error('Usage: yak-handler.js y://...');
  process.exit(1);
}

// Convert to HTTP URL
const httpUrl = yakToHttp(url, PORT);

// SECURITY: Validate the generated URL is actually a localhost HTTP URL.
// This prevents any crafted yak:// URL from generating a malicious target.
try {
  const parsed = new (require('url').URL)(httpUrl);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    console.error('Security: Generated URL has invalid protocol:', parsed.protocol);
    process.exit(1);
  }
  if (parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
    console.error('Security: Generated URL points to non-local host:', parsed.hostname);
    process.exit(1);
  }
} catch (e) {
  console.error('Security: Generated URL is malformed:', e.message);
  process.exit(1);
}

console.log(`Y Protocol: ${url}`);
console.log(`   -> ${httpUrl}`);

// Open in default browser using execFile (no shell) to prevent injection.
// Each OS gets its opener binary called directly with the URL as an argument,
// never concatenated into a shell string.
const os = platform();
let opener;
let args;

switch (os) {
  case 'win32':
    opener = 'cmd.exe';
    args = ['/c', 'start', '', httpUrl];
    break;
  case 'darwin':
    opener = '/usr/bin/open';
    args = [httpUrl];
    break;
  default:
    opener = '/usr/bin/xdg-open';
    args = [httpUrl];
}

execFile(opener, args, (error) => {
  if (error) {
    console.error('Failed to open browser:', error.message);
    process.exit(1);
  }
});
