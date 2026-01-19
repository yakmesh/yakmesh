#!/usr/bin/env node
/**
 * Y:// Protocol Handler Executable
 * This script is invoked by the OS when a y:// URL is clicked.
 * 
 * Self-contained - no ES module imports for compatibility.
 */

const { exec } = require('child_process');
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

console.log(`🦬 Y Protocol: ${url}`);
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
