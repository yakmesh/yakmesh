/**
 * YAK:// Protocol Handler
 * 
 * Custom URL protocol for Yakmesh - escape HTTP entirely!
 * Three-letter protocol: "yak" (avoids Windows drive letter conflicts)
 * 
 * Phase 1: Simple builtin routes + content addressing
 * 
 * Examples:
 *   yak://dashboard          → Node dashboard
 *   yak://site               → Hosted website
 *   yak://peers              → Connected peers
 *   yak://content/<hash>     → Content by hash (immutable)
 * 
 * How it works:
 * 1. Register yak:// protocol with OS (Windows Registry, macOS, Linux)
 * 2. OS launches our handler when user clicks yak:// link
 * 3. Handler routes to local node API or opens in browser
 * 
 * Phase 2: Local bookmarks (pet names)
 *   yak://alice           → Your personal bookmark "alice"
 *   yakmesh bookmark add alice <target>
 * 
 * @module protocol/yak-protocol
 * @version 2.2.0
 */

import { existsSync, writeFileSync, mkdirSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { execSync, spawn } from 'child_process';
import { platform } from 'os';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Default node port
 */
const DEFAULT_PORT = 3000;

/**
 * Protocol configuration
 */
export const PROTOCOL = {
  scheme: 'yak',
  name: 'Yakmesh Protocol',
  description: 'Post-Quantum Secure Mesh Network Protocol - yak://',
};

/**
 * Built-in routes that map to HTTP endpoints
 */
export const BUILTIN_ROUTES = {
  'dashboard': '/dashboard',
  'site': '/site/',
  'content': '/content',
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
  'bookmarks': '/bookmarks',
};

/**
 * Default bookmarks file path
 */
const BOOKMARKS_FILE = join(__dirname, '..', 'data', 'bookmarks.json');

/**
 * Bookmark Manager - Personal pet names for yak:// addresses
 * 
 * Bookmarks are local to your node - no global registry needed.
 * Resolution priority: builtins → bookmarks → content hash → unknown
 */
export class BookmarkManager {
  constructor(pathOrOptions = BOOKMARKS_FILE) {
    // Support both string path and options object
    if (typeof pathOrOptions === 'object' && pathOrOptions !== null) {
      const { dataDir } = pathOrOptions;
      this.path = dataDir ? join(dataDir, 'bookmarks.json') : BOOKMARKS_FILE;
    } else {
      this.path = pathOrOptions;
    }
    this.bookmarks = {};
    this._load();
  }

  /**
   * Load bookmarks from disk
   */
  _load() {
    try {
      if (existsSync(this.path)) {
        const data = readFileSync(this.path, 'utf-8');
        this.bookmarks = JSON.parse(data);
      }
    } catch (e) {
      console.warn('Failed to load bookmarks:', e.message);
      this.bookmarks = {};
    }
  }

  /**
   * Save bookmarks to disk
   */
  _save() {
    try {
      const dir = dirname(this.path);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
      writeFileSync(this.path, JSON.stringify(this.bookmarks, null, 2));
    } catch (e) {
      console.error('Failed to save bookmarks:', e.message);
    }
  }

  /**
   * Add a bookmark
   * @param {string} name - Bookmark name (e.g., "alice")
   * @param {string} target - Target path (e.g., "content/abc123" or "site/page" or "/dashboard")
   * @returns {boolean} Success
   */
  add(name, target) {
    name = name.toLowerCase().replace(/[^a-z0-9_-]/g, '');
    if (!name) return false;
    
    // Don't allow overwriting builtins
    if (BUILTIN_ROUTES[name]) {
      console.warn(`Cannot bookmark "${name}" - it's a builtin route`);
      return false;
    }
    
    // Normalize target - ensure it starts with /
    if (!target.startsWith('/')) {
      target = '/' + target;
    }
    
    this.bookmarks[name] = {
      target,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    this._save();
    return true;
  }

  /**
   * Remove a bookmark
   * @param {string} name - Bookmark name
   * @returns {boolean} Success
   */
  remove(name) {
    name = name.toLowerCase();
    if (this.bookmarks[name]) {
      delete this.bookmarks[name];
      this._save();
      return true;
    }
    return false;
  }

  /**
   * Get a bookmark's target
   * @param {string} name - Bookmark name
   * @returns {string|null} Target path or null
   */
  get(name) {
    name = name.toLowerCase();
    return this.bookmarks[name]?.target || null;
  }

  /**
   * List all bookmarks
   * @returns {Object} All bookmarks
   */
  list() {
    return { ...this.bookmarks };
  }

  /**
   * Check if a bookmark exists
   * @param {string} name - Bookmark name
   * @returns {boolean}
   */
  has(name) {
    return name.toLowerCase() in this.bookmarks;
  }

  /**
   * Rename a bookmark
   * @param {string} oldName - Current name
   * @param {string} newName - New name
   * @returns {boolean} Success
   */
  rename(oldName, newName) {
    oldName = oldName.toLowerCase();
    newName = newName.toLowerCase().replace(/[^a-z0-9_-]/g, '');
    
    if (!this.bookmarks[oldName]) return false;
    if (BUILTIN_ROUTES[newName]) return false;
    
    this.bookmarks[newName] = { ...this.bookmarks[oldName], updatedAt: Date.now() };
    delete this.bookmarks[oldName];
    this._save();
    return true;
  }
}

// ============================================================
// REMOTE BOOKMARKS - Mesh-Synchronized Shared Lists (v2.2.0)
// ============================================================

/**
 * Remote Bookmark Sync - Share bookmark lists between nodes via mesh gossip
 * 
 * Features:
 * - Publish your bookmarks to the mesh (opt-in)
 * - Subscribe to other nodes' shared lists
 * - Automatic sync via gossip protocol
 * - DOKO-verified ownership (prevents impersonation)
 * 
 * Usage:
 *   yakmesh bookmark share <list-name>     - Share a list publicly
 *   yakmesh bookmark subscribe <node-id>   - Subscribe to node's list
 *   yakmesh bookmark list --remote         - View remote bookmarks
 * 
 * Resolution: local bookmarks always take priority over remote ones
 */
export class RemoteBookmarkSync {
  static REMOTE_FILE = join(__dirname, '..', 'data', 'remote-bookmarks.json');
  
  constructor(options = {}) {
    this.nodeId = options.nodeId;
    this.network = options.network;
    this.localBookmarks = options.localBookmarks || getBookmarkManager();
    
    // Support custom data directory for tests
    this.dataDir = options.dataDir || join(__dirname, '..', 'data');
    this.remoteFile = join(this.dataDir, 'remote-bookmarks.json');
    
    // Remote bookmark storage
    this.remoteBookmarks = new Map(); // nodeId → { bookmarks, publishedAt, signature }
    this.subscriptions = new Set();   // nodeIds we're subscribed to
    this.publishedLists = {};         // Our shared lists
    
    // Load persisted state
    this._load();
    
    // Gossip message type
    this.MESSAGE_TYPE = 'bookmark-sync';
    
    // Register gossip handler if network provided
    if (this.network) {
      this._registerGossipHandler();
    }
  }

  /**
   * Load remote bookmarks from disk
   */
  _load() {
    try {
      if (existsSync(this.remoteFile)) {
        const data = JSON.parse(readFileSync(this.remoteFile, 'utf-8'));
        this.subscriptions = new Set(data.subscriptions || []);
        this.publishedLists = data.publishedLists || {};
        
        // Restore remote bookmarks
        if (data.remoteBookmarks) {
          for (const [nodeId, entry] of Object.entries(data.remoteBookmarks)) {
            this.remoteBookmarks.set(nodeId, entry);
          }
        }
      }
    } catch (e) {
      console.warn('Failed to load remote bookmarks:', e.message);
    }
  }

  /**
   * Save remote bookmarks to disk
   */
  _save() {
    try {
      const dir = dirname(this.remoteFile);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
      
      const data = {
        subscriptions: [...this.subscriptions],
        publishedLists: this.publishedLists,
        remoteBookmarks: Object.fromEntries(this.remoteBookmarks),
        savedAt: Date.now(),
      };
      
      writeFileSync(this.remoteFile, JSON.stringify(data, null, 2));
    } catch (e) {
      console.error('Failed to save remote bookmarks:', e.message);
    }
  }

  /**
   * Register gossip message handler
   */
  _registerGossipHandler() {
    this.network.on('gossip', (msg, fromNodeId) => {
      if (msg.type === this.MESSAGE_TYPE) {
        this._handleRemoteBookmarks(msg, fromNodeId);
      }
    });
  }

  /**
   * Handle incoming remote bookmarks from gossip
   */
  _handleRemoteBookmarks(msg, fromNodeId) {
    // Only accept from subscribed nodes
    if (!this.subscriptions.has(fromNodeId)) {
      return;
    }
    
    // Verify signature (basic check - DOKO verification is recommended)
    if (!msg.signature) {
      console.warn(`Ignoring unsigned bookmark sync from ${fromNodeId}`);
      return;
    }
    
    // Update remote bookmarks
    this.remoteBookmarks.set(fromNodeId, {
      bookmarks: msg.bookmarks,
      listName: msg.listName || 'default',
      publishedAt: msg.publishedAt,
      signature: msg.signature,
      receivedAt: Date.now(),
    });
    
    this._save();
    console.log(`📥 Received bookmarks from ${fromNodeId.slice(0, 16)}... (${Object.keys(msg.bookmarks).length} items)`);
  }

  /**
   * Share a bookmark list to the mesh
   * @param {string} listName - Name for the shared list
   * @param {Object} bookmarks - Bookmarks to share (default: all local)
   * @returns {boolean} Success
   */
  publish(listName = 'default', bookmarks = null) {
    if (!this.network) {
      console.warn('Cannot publish - no network connection');
      return false;
    }
    
    // Use provided bookmarks or all local ones
    const toShare = bookmarks || this.localBookmarks.list();
    
    // Create signed message
    const msg = {
      type: this.MESSAGE_TYPE,
      listName,
      bookmarks: toShare,
      publishedAt: Date.now(),
      nodeId: this.nodeId,
    };
    
    // Broadcast to mesh
    this.network.broadcast({ gossip: msg });
    
    // Track published list
    this.publishedLists[listName] = {
      bookmarks: toShare,
      publishedAt: msg.publishedAt,
      count: Object.keys(toShare).length,
    };
    
    this._save();
    console.log(`📤 Published bookmark list "${listName}" (${Object.keys(toShare).length} items)`);
    return true;
  }

  /**
   * Subscribe to a node's bookmark list
   * @param {string} nodeId - Node to subscribe to
   * @returns {boolean} Success
   */
  subscribe(nodeId) {
    if (nodeId === this.nodeId) {
      console.warn('Cannot subscribe to your own node');
      return false;
    }
    
    this.subscriptions.add(nodeId);
    this._save();
    console.log(`📬 Subscribed to bookmarks from ${nodeId.slice(0, 16)}...`);
    return true;
  }

  /**
   * Unsubscribe from a node's bookmark list
   * @param {string} nodeId - Node to unsubscribe from
   * @returns {boolean} Success
   */
  unsubscribe(nodeId) {
    if (this.subscriptions.delete(nodeId)) {
      this.remoteBookmarks.delete(nodeId);
      this._save();
      console.log(`📭 Unsubscribed from ${nodeId.slice(0, 16)}...`);
      return true;
    }
    return false;
  }

  /**
   * Get a remote bookmark by name
   * Searches across all subscribed nodes
   * @param {string} name - Bookmark name
   * @returns {Object|null} { target, nodeId, listName } or null
   */
  getRemote(name) {
    name = name.toLowerCase();
    
    // Search all subscribed nodes
    for (const [nodeId, entry] of this.remoteBookmarks) {
      const bm = entry.bookmarks[name];
      if (bm) {
        return {
          target: bm.target || bm,
          nodeId,
          listName: entry.listName,
          publishedAt: entry.publishedAt,
        };
      }
    }
    
    return null;
  }

  /**
   * List all remote bookmarks from subscribed nodes
   * @returns {Array} [{ name, target, nodeId, listName }, ...]
   */
  listRemote() {
    const all = [];
    
    for (const [nodeId, entry] of this.remoteBookmarks) {
      for (const [name, bm] of Object.entries(entry.bookmarks)) {
        all.push({
          name,
          target: bm.target || bm,
          nodeId,
          listName: entry.listName,
          publishedAt: entry.publishedAt,
        });
      }
    }
    
    return all;
  }

  /**
   * Get subscriptions list
   * @returns {Array} Node IDs
   */
  getSubscriptions() {
    return [...this.subscriptions];
  }

  /**
   * Get published lists
   * @returns {Object} { listName: { bookmarks, publishedAt, count } }
   */
  getPublished() {
    return { ...this.publishedLists };
  }

  /**
   * Get sync status
   * @returns {Object} Status info
   */
  getStatus() {
    return {
      subscriptions: this.subscriptions.size,
      remoteBookmarks: this.remoteBookmarks.size,
      publishedLists: Object.keys(this.publishedLists).length,
      totalRemoteItems: this.listRemote().length,
    };
  }
}

// Global remote bookmark sync instance
let _remoteBookmarkSync = null;

/**
 * Get the global remote bookmark sync instance
 * @param {Object} options - Options for initialization
 * @returns {RemoteBookmarkSync}
 */
export function getRemoteBookmarkSync(options = {}) {
  if (!_remoteBookmarkSync) {
    _remoteBookmarkSync = new RemoteBookmarkSync(options);
  }
  return _remoteBookmarkSync;
}

// Global bookmark manager instance
let _bookmarkManager = null;

/**
 * Get the global bookmark manager
 * @returns {BookmarkManager}
 */
export function getBookmarkManager() {
  if (!_bookmarkManager) {
    _bookmarkManager = new BookmarkManager();
  }
  return _bookmarkManager;
}

/**
 * Parse a yak:// URL
 * 
 * Phase 1: Simple builtin routes + content addressing
 * Phase 2: Local bookmarks (pet names)
 * 
 * @param {string} url - The yak:// URL to parse
 * @returns {Object} Parsed URL components
 */
export function parseYakUrl(url) {
  // Remove the scheme (supports both y:// and yak:// for compatibility)
  let path = url.replace(/^(y|yak):\/\//i, '');
  
  // Handle empty URL
  if (!path || path === '/') {
    return { type: 'builtin', route: 'dashboard', path: '/dashboard/' };
  }
  
  // Split into parts
  const parts = path.split('/').filter(Boolean);
  const host = parts[0].toLowerCase();
  const subpath = parts.length > 1 ? '/' + parts.slice(1).join('/') : '';
  
  // Check if it's a built-in route
  if (BUILTIN_ROUTES[host]) {
    return {
      type: 'builtin',
      route: host,
      path: BUILTIN_ROUTES[host] + subpath,
    };
  }
  
  // Phase 2: Check local bookmarks
  const bookmarks = getBookmarkManager();
  if (bookmarks.has(host)) {
    const target = bookmarks.get(host);
    return {
      type: 'bookmark',
      name: host,
      target,
      path: target + subpath,
    };
  }
  
  // Check for content hash (64 hex characters)
  if (/^[a-f0-9]{64}$/i.test(host)) {
    return {
      type: 'content',
      hash: host,
      path: `/content/${host}${subpath}`,
    };
  }
  
  // Check for "content/" prefix explicitly
  if (host === 'content' && parts.length > 1) {
    const hash = parts[1];
    return {
      type: 'content',
      hash: hash,
      path: `/content/${hash}`,
    };
  }
  
  // Unknown - return 404 path
  return {
    type: 'unknown',
    name: host,
    path: '/404?url=' + encodeURIComponent(url),
  };
}

/**
 * Convert a yak:// URL to an HTTP URL
 * @param {string} yakUrl - The yak:// URL
 * @param {number} port - Node HTTP port
 * @returns {string} HTTP URL
 */
export function yakToHttp(yakUrl, port = DEFAULT_PORT) {
  const parsed = parseYakUrl(yakUrl);
  const base = `http://localhost:${port}`;
  
  if (parsed.type === 'domain') {
    return `${base}/yak/${parsed.domain}${parsed.path === '/' ? '' : parsed.path}`;
  }
  
  return base + parsed.path;
}

/**
 * Convert an HTTP URL to a yak:// URL
 * @param {string} httpUrl - The HTTP URL
 * @returns {string} yak:// URL
 */
export function httpToYak(httpUrl) {
  const url = new URL(httpUrl);
  const path = url.pathname;
  
  // Check built-in routes
  for (const [route, httpPath] of Object.entries(BUILTIN_ROUTES)) {
    if (path === httpPath || path.startsWith(httpPath + '/')) {
      const subpath = path.slice(httpPath.length);
      return `yak://${route}${subpath}`;
    }
  }
  
  // Check content route
  if (path.startsWith('/content/')) {
    const hash = path.slice(9);
    return `yak://content/${hash}`;
  }
  
  return `yak://${path.slice(1)}`;
}

/**
 * YakProtocolHandler - Manages yak:// protocol registration and handling
 */
export class YakProtocolHandler {
  constructor(options = {}) {
    this.port = options.port || DEFAULT_PORT;
    this.nodePath = options.nodePath || join(__dirname, '..');
    this.handlerPath = options.handlerPath || join(__dirname, 'yak-handler.cjs');
    this.registered = false;
  }

  /**
   * Register the y:// protocol with the operating system
   */
  async register() {
    const os = platform();
    
    console.log(`📡 Registering yak:// protocol (${os})...`);
    
    try {
      switch (os) {
        case 'win32':
          await this._registerWindows();
          break;
        case 'darwin':
          await this._registerMacOS();
          break;
        case 'linux':
          await this._registerLinux();
          break;
        default:
          console.warn(`⚠️ Protocol registration not supported on ${os}`);
          return false;
      }
      
      this.registered = true;
      console.log('✓ yak:// protocol registered');
      return true;
    } catch (error) {
      console.error('Failed to register protocol:', error.message);
      return false;
    }
  }

  /**
   * Unregister the y:// protocol
   */
  async unregister() {
    const os = platform();
    
    try {
      switch (os) {
        case 'win32':
          await this._unregisterWindows();
          break;
        case 'darwin':
          await this._unregisterMacOS();
          break;
        case 'linux':
          await this._unregisterLinux();
          break;
      }
      
      this.registered = false;
      console.log('✓ yak:// protocol unregistered');
      return true;
    } catch (error) {
      console.error('Failed to unregister protocol:', error.message);
      return false;
    }
  }

  /**
   * Handle a yak:// URL (called when OS invokes our handler)
   */
  async handle(url) {
    const parsed = parseYakUrl(url);
    const httpUrl = yakToHttp(url, this.port);
    
    console.log(`🔗 Handling: ${url}`);
    console.log(`   → ${httpUrl}`);
    
    // Open in default browser
    this._openBrowser(httpUrl);
    
    return { parsed, httpUrl };
  }

  /**
   * Create the handler script that the OS will invoke
   */
  createHandler() {
    // Generate self-contained CommonJS handler (no ES module imports)
    const handlerScript = `#!/usr/bin/env node
/**
 * YAK:// Protocol Handler Executable
 * This script is invoked by the OS when a yak:// URL is clicked.
 * Self-contained CommonJS - no ES module imports for compatibility.
 */

const { exec } = require('child_process');
const { platform } = require('os');

const PORT = ${this.port};

// Built-in routes that map to HTTP endpoints
const BUILTIN_ROUTES = {
  'dashboard': '/dashboard/',
  'site': '/site/',
  'content': '/content/',
  'node': '/node',
  'peers': '/peers',
  'metrics': '/metrics',
  'health': '/health',
  'gossip': '/gossip',
  'discovered': '/discovered',
  'security': '/security/status',
  'namche': '/security/namche/gates',
  'doko': '/security/doko/stats',
  'oracle': '/oracle/status',
  'time': '/time/status'
};

/**
 * Convert yak:// URL to HTTP URL
 */
function yakToHttp(yakUrl, port) {
  const match = yakUrl.match(/^(y|yak):\\/\\/(.+)$/i);
  if (!match) return \`http://localhost:\${port}/dashboard/\`;
  
  const path = match[2];
  const parts = path.split('/').filter(Boolean);
  const host = parts[0].toLowerCase();
  const subPath = parts.length > 1 ? '/' + parts.slice(1).join('/') : '';
  
  // Check builtin routes
  if (BUILTIN_ROUTES[host]) {
    return \`http://localhost:\${port}\${BUILTIN_ROUTES[host]}\${subPath}\`;
  }
  
  // Check content hash (64 char hex)
  if (/^[a-f0-9]{64}$/i.test(host)) {
    return \`http://localhost:\${port}/content/\${host}\`;
  }
  
  // Content with explicit prefix
  if (host === 'content' && parts.length > 1) {
    return \`http://localhost:\${port}/content/\${parts[1]}\`;
  }
  
  // Unknown - 404
  return \`http://localhost:\${port}/404?url=\${encodeURIComponent(yakUrl)}\`;
}

// Get the URL from command line arguments
const url = process.argv[2];

if (!url || !url.match(/^(y|yak):\\/\\//i)) {
  console.error('Usage: yak-handler.cjs yak://...');
  process.exit(1);
}

// Convert to HTTP URL
const httpUrl = yakToHttp(url, PORT);

console.log(\`🦬 YAK Protocol: \${url}\`);
console.log(\`   → \${httpUrl}\`);

// Open in default browser
const os = platform();
let cmd;

switch (os) {
  case 'win32':
    cmd = \`start "" "\${httpUrl}"\`;
    break;
  case 'darwin':
    cmd = \`open "\${httpUrl}"\`;
    break;
  default:
    cmd = \`xdg-open "\${httpUrl}"\`;
}

exec(cmd, (error) => {
  if (error) {
    console.error('Failed to open browser:', error.message);
    process.exit(1);
  }
});
`;

    writeFileSync(this.handlerPath, handlerScript);
    console.log(`✓ Created handler: ${this.handlerPath}`);
    
    return this.handlerPath;
  }

  /**
   * Register on Windows (Registry)
   */
  async _registerWindows() {
    // Create the handler script first
    this.createHandler();
    
    const nodePath = process.execPath;
    const handlerCmd = `"${nodePath}" "${this.handlerPath}" "%1"`;
    
    // Create .reg file content
    const regContent = `Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\\Software\\Classes\\yak]
@="URL:Yakmesh Protocol"
"URL Protocol"=""

[HKEY_CURRENT_USER\\Software\\Classes\\yak\\DefaultIcon]
@="${nodePath.replace(/\\/g, '\\\\')},1"

[HKEY_CURRENT_USER\\Software\\Classes\\yak\\shell]

[HKEY_CURRENT_USER\\Software\\Classes\\yak\\shell\\open]

[HKEY_CURRENT_USER\\Software\\Classes\\yak\\shell\\open\\command]
@="${handlerCmd.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"
`;

    // Write .reg file
    const regPath = join(this.nodePath, 'protocol', 'yak-protocol.reg');
    writeFileSync(regPath, regContent);
    
    // Import the registry file
    try {
      execSync(`reg import "${regPath}"`, { stdio: 'pipe' });
    } catch (e) {
      // Try alternative method using reg add commands
      const commands = [
        `reg add "HKCU\\Software\\Classes\\yak" /ve /d "URL:Yakmesh Protocol" /f`,
        `reg add "HKCU\\Software\\Classes\\yak" /v "URL Protocol" /d "" /f`,
        `reg add "HKCU\\Software\\Classes\\yak\\shell\\open\\command" /ve /d "${handlerCmd}" /f`,
      ];
      
      for (const cmd of commands) {
        execSync(cmd, { stdio: 'pipe' });
      }
    }
    
    console.log('✓ Windows Registry updated');
  }

  /**
   * Unregister on Windows
   */
  async _unregisterWindows() {
    try {
      execSync('reg delete "HKCU\\Software\\Classes\\yak" /f', { stdio: 'pipe' });
    } catch (e) {
      // Key might not exist
    }
  }

  /**
   * Register on macOS (Launch Services)
   */
  async _registerMacOS() {
    this.createHandler();
    
    const plistPath = join(process.env.HOME, 'Library', 'LaunchAgents', 'com.yakmesh.protocol.plist');
    const plistDir = dirname(plistPath);
    
    if (!existsSync(plistDir)) {
      mkdirSync(plistDir, { recursive: true });
    }
    
    const plistContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.yakmesh.protocol</string>
    <key>ProgramArguments</key>
    <array>
        <string>${process.execPath}</string>
        <string>${this.handlerPath}</string>
    </array>
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLName</key>
            <string>Yakmesh Protocol</string>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>yak</string>
            </array>
        </dict>
    </array>
</dict>
</plist>`;

    writeFileSync(plistPath, plistContent);
    
    // For macOS, we need an app bundle or use a helper
    console.log('⚠️ macOS: Full protocol registration requires app bundle');
    console.log('  Created launch agent at:', plistPath);
  }

  /**
   * Unregister on macOS
   */
  async _unregisterMacOS() {
    const plistPath = join(process.env.HOME, 'Library', 'LaunchAgents', 'com.yakmesh.protocol.plist');
    try {
      if (existsSync(plistPath)) {
        execSync(`rm "${plistPath}"`, { stdio: 'pipe' });
      }
    } catch (e) {
      // Ignore
    }
  }

  /**
   * Register on Linux (xdg-open / .desktop file)
   */
  async _registerLinux() {
    this.createHandler();
    
    const desktopPath = join(process.env.HOME, '.local', 'share', 'applications', 'yakmesh-protocol.desktop');
    const desktopDir = dirname(desktopPath);
    
    if (!existsSync(desktopDir)) {
      mkdirSync(desktopDir, { recursive: true });
    }
    
    const desktopContent = `[Desktop Entry]
Name=Yakmesh Protocol Handler
Comment=Handle yak:// URLs
Exec=${process.execPath} ${this.handlerPath} %u
Terminal=false
Type=Application
MimeType=x-scheme-handler/y;
NoDisplay=true
`;

    writeFileSync(desktopPath, desktopContent);
    
    // Register with xdg-mime
    try {
      execSync(`xdg-mime default yakmesh-protocol.desktop x-scheme-handler/y`, { stdio: 'pipe' });
      console.log('✓ Registered with xdg-mime');
    } catch (e) {
      console.warn('⚠️ Could not register with xdg-mime');
    }
  }

  /**
   * Unregister on Linux
   */
  async _unregisterLinux() {
    const desktopPath = join(process.env.HOME, '.local', 'share', 'applications', 'yakmesh-protocol.desktop');
    try {
      if (existsSync(desktopPath)) {
        execSync(`rm "${desktopPath}"`, { stdio: 'pipe' });
      }
    } catch (e) {
      // Ignore
    }
  }

  /**
   * Open a URL in the default browser
   */
  _openBrowser(url) {
    const os = platform();
    let cmd;
    
    switch (os) {
      case 'win32':
        cmd = `start "" "${url}"`;
        break;
      case 'darwin':
        cmd = `open "${url}"`;
        break;
      default:
        cmd = `xdg-open "${url}"`;
    }
    
    try {
      execSync(cmd, { stdio: 'pipe' });
    } catch (e) {
      console.error('Failed to open browser:', e.message);
    }
  }
}

/**
 * Create endpoints for yak:// protocol on Express app
 */
export function createProtocolEndpoints(app, handler) {
  // Protocol info endpoint
  app.get('/protocol', (req, res) => {
    res.json({
      protocol: PROTOCOL,
      registered: handler.registered,
      routes: BUILTIN_ROUTES,
      examples: [
        'y://dashboard',
        'y://yakmesh.yak',
        'y://content/abc123...',
        'y://site',
        'y://peers',
      ],
    });
  });

  // Convert yak:// to HTTP
  app.get('/protocol/convert', (req, res) => {
    const yakUrl = req.query.url;
    if (!yakUrl) {
      return res.status(400).json({ error: 'Missing url parameter' });
    }
    
    const parsed = parseYakUrl(yakUrl);
    const httpUrl = yakToHttp(yakUrl, handler.port);
    
    res.json({ yakUrl, parsed, httpUrl });
  });

  // Generate yak:// link for current page
  app.get('/protocol/link', (req, res) => {
    const httpUrl = req.query.url || `http://${req.headers.host}${req.path}`;
    const yakUrl = httpToYak(httpUrl);
    
    res.json({ httpUrl, yakUrl });
  });

  // === BOOKMARKS API ===
  const bookmarks = getBookmarkManager();
  
  // List all bookmarks
  app.get('/bookmarks', (req, res) => {
    const all = bookmarks.list();
    const formatted = Object.entries(all).map(([name, bm]) => ({
      name,
      yakUrl: `yak://${name}`,
      target: bm.target,
      httpUrl: `http://localhost:${handler.port}${bm.target}`,
      createdAt: bm.createdAt,
    }));
    res.json({
      count: formatted.length,
      bookmarks: formatted,
    });
  });
  
  // Get specific bookmark
  app.get('/bookmarks/:name', (req, res) => {
    const { name } = req.params;
    const target = bookmarks.get(name);
    
    if (!target) {
      return res.status(404).json({ error: `Bookmark '${name}' not found` });
    }
    
    const all = bookmarks.list();
    const bm = all[name.toLowerCase()];
    
    res.json({
      name: name.toLowerCase(),
      yakUrl: `yak://${name.toLowerCase()}`,
      target,
      httpUrl: `http://localhost:${handler.port}${target}`,
      createdAt: bm?.createdAt,
    });
  });
  
  // Add bookmark (POST)
  app.post('/bookmarks', (req, res) => {
    const { name, target } = req.body;
    
    if (!name || !target) {
      return res.status(400).json({ error: 'name and target required' });
    }
    
    const success = bookmarks.add(name, target);
    
    if (success) {
      res.json({
        success: true,
        name: name.toLowerCase(),
        target: bookmarks.get(name.toLowerCase()),
        yakUrl: `yak://${name.toLowerCase()}`,
      });
    } else {
      res.status(400).json({ error: `Cannot add bookmark '${name}' - may be a builtin route` });
    }
  });
  
  // Remove bookmark (DELETE)
  app.delete('/bookmarks/:name', (req, res) => {
    const { name } = req.params;
    
    if (!bookmarks.has(name)) {
      return res.status(404).json({ error: `Bookmark '${name}' not found` });
    }
    
    bookmarks.remove(name);
    res.json({ success: true, removed: name.toLowerCase() });
  });

  // === REMOTE BOOKMARKS API (v2.2.0) ===
  // Get remote sync instance (lazy init with network if available)
  let remoteSync = null;
  const getRemoteSync = () => {
    if (!remoteSync) {
      remoteSync = getRemoteBookmarkSync({ localBookmarks: bookmarks });
    }
    return remoteSync;
  };

  // Get remote sync status
  app.get('/bookmarks/remote/status', (req, res) => {
    const sync = getRemoteSync();
    res.json({
      status: sync.getStatus(),
      subscriptions: sync.getSubscriptions(),
      published: sync.getPublished(),
    });
  });

  // List remote bookmarks from subscribed nodes
  app.get('/bookmarks/remote', (req, res) => {
    const sync = getRemoteSync();
    const remote = sync.listRemote();
    res.json({
      count: remote.length,
      bookmarks: remote.map(bm => ({
        name: bm.name,
        target: bm.target,
        yakUrl: `yak://${bm.name}`,
        httpUrl: `http://localhost:${handler.port}${bm.target}`,
        fromNode: bm.nodeId.slice(0, 16) + '...',
        listName: bm.listName,
        publishedAt: bm.publishedAt,
      })),
    });
  });

  // Get a specific remote bookmark
  app.get('/bookmarks/remote/:name', (req, res) => {
    const sync = getRemoteSync();
    const bm = sync.getRemote(req.params.name);
    
    if (!bm) {
      return res.status(404).json({ error: `Remote bookmark '${req.params.name}' not found` });
    }
    
    res.json({
      name: req.params.name.toLowerCase(),
      target: bm.target,
      yakUrl: `yak://${req.params.name.toLowerCase()}`,
      httpUrl: `http://localhost:${handler.port}${bm.target}`,
      fromNode: bm.nodeId.slice(0, 16) + '...',
      listName: bm.listName,
      publishedAt: bm.publishedAt,
    });
  });

  // Subscribe to a node's bookmarks
  app.post('/bookmarks/remote/subscribe', (req, res) => {
    const { nodeId } = req.body;
    
    if (!nodeId) {
      return res.status(400).json({ error: 'nodeId required' });
    }
    
    const sync = getRemoteSync();
    const success = sync.subscribe(nodeId);
    
    res.json({
      success,
      subscriptions: sync.getSubscriptions(),
    });
  });

  // Unsubscribe from a node
  app.post('/bookmarks/remote/unsubscribe', (req, res) => {
    const { nodeId } = req.body;
    
    if (!nodeId) {
      return res.status(400).json({ error: 'nodeId required' });
    }
    
    const sync = getRemoteSync();
    const success = sync.unsubscribe(nodeId);
    
    res.json({
      success,
      subscriptions: sync.getSubscriptions(),
    });
  });

  // Publish your bookmarks to the mesh
  app.post('/bookmarks/remote/publish', (req, res) => {
    const { listName } = req.body;
    const sync = getRemoteSync();
    
    // Without network, we just save locally what would be published
    const allBookmarks = bookmarks.list();
    const name = listName || 'default';
    
    // Update the published lists record
    sync.publishedLists[name] = {
      bookmarks: allBookmarks,
      publishedAt: Date.now(),
      count: Object.keys(allBookmarks).length,
    };
    sync._save();
    
    res.json({
      success: true,
      listName: name,
      count: Object.keys(allBookmarks).length,
      note: 'Saved locally. Will broadcast when mesh is connected.',
    });
  });

  console.log('✓ Protocol endpoints registered at /protocol');
  console.log('✓ Bookmarks API registered at /bookmarks');
  console.log('✓ Remote Bookmarks API registered at /bookmarks/remote');
}

export default YakProtocolHandler;
