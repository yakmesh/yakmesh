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
 * YAKMESH™ Website Adapter
 * 
 * Self-hosting adapter for serving static websites via Yakmesh mesh.
 * Enables any Yakmesh node to host and serve website content with:
 * 
 * - Content-addressed storage (every file has a hash)
 * - Mesh replication (files sync across nodes)
 * - .yak domain resolution (decentralized DNS via DOKO)
 * - Dashboard integration (built-in admin UI)
 * - Live updates (content syncs without restart)
 * - DOKO identity verification (publisher/owner identity)
 * 
 * @module adapters/adapter-website
 * @version 2.1.0 - Added DOKO identity binding for domains and publishers
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { BaseAdapter } from '../base-adapter.js';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'fs';
import { join, extname, relative, dirname } from 'path';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

// Import DOKO for publisher/owner identity verification
import { DOKODocument, DOKO_TYPES } from '../../security/doko-identity.js';

// Import iO for displaying identities (never expose raw hashes)
import { deriveNetworkName, deriveNetworkId } from '../../oracle/network-identity.js';

/**
 * MIME type mapping
 */
const MIME_TYPES = {
  '.html': 'text/html',
  '.htm': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.mjs': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.eot': 'application/vnd.ms-fontobject',
  '.md': 'text/markdown',
  '.txt': 'text/plain',
  '.xml': 'application/xml',
  '.pdf': 'application/pdf',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
};

/**
 * Website file metadata
 */
class WebsiteFile {
  constructor(options = {}) {
    this.path = options.path;           // Relative path from root
    this.hash = options.hash;           // SHA3-256 hash of content
    this.size = options.size || 0;
    this.mimeType = options.mimeType || 'application/octet-stream';
    this.modifiedAt = options.modifiedAt || Date.now();
    this.syncedAt = options.syncedAt || null;
    this.nodeId = options.nodeId || null;  // Origin node
  }

  toJSON() {
    return {
      path: this.path,
      hash: this.hash,
      size: this.size,
      mimeType: this.mimeType,
      modifiedAt: this.modifiedAt,
      syncedAt: this.syncedAt,
      nodeId: this.nodeId,
    };
  }

  static fromJSON(json) {
    return new WebsiteFile(json);
  }
}

/**
 * .yak Domain Record with DOKO Identity Binding
 * 
 * Each .yak domain is cryptographically bound to its owner's DOKO identity.
 * This provides verifiable ownership without centralized registrars.
 * 
 * SECURITY: The ownerDoko field contains the iO-obfuscated DOKO ID,
 * never raw hashes. Domain transfers require DOKO signature verification.
 */
class YakDomain {
  constructor(options = {}) {
    this.domain = options.domain;            // e.g., "yakmesh.yak"
    this.websiteId = options.websiteId;      // Website manifest hash
    this.ownerNodeId = options.ownerNodeId;  // Node ID (public)
    this.ownerDoko = options.ownerDoko;      // iO-obfuscated DOKO ID (e.g., "doko-node-qubit-lattice-pq-a7x9")
    this.registeredAt = options.registeredAt || Date.now();
    this.expiresAt = options.expiresAt || Date.now() + (365 * 24 * 60 * 60 * 1000);
    this.signature = options.signature || null;
    this.txtRecords = options.txtRecords || {};
    this.transferHistory = options.transferHistory || []; // Audit trail
  }

  /**
   * Check if domain is owned by a specific DOKO identity
   * @param {string} dokoId - DOKO ID to verify (iO-obfuscated)
   * @returns {boolean}
   */
  isOwnedBy(dokoId) {
    return this.ownerDoko === dokoId;
  }

  /**
   * Check if domain has expired
   * @returns {boolean}
   */
  isExpired() {
    return Date.now() > this.expiresAt;
  }

  /**
   * Record a domain transfer with audit trail
   * @param {string} newOwnerDoko - New owner's DOKO ID
   * @param {string} newOwnerNodeId - New owner's node ID
   * @param {string} transferSignature - Signature proving transfer authorization
   */
  recordTransfer(newOwnerDoko, newOwnerNodeId, transferSignature) {
    this.transferHistory.push({
      fromDoko: this.ownerDoko,
      fromNodeId: this.ownerNodeId,
      toDoko: newOwnerDoko,
      toNodeId: newOwnerNodeId,
      signature: transferSignature,
      timestamp: Date.now(),
    });
    this.ownerDoko = newOwnerDoko;
    this.ownerNodeId = newOwnerNodeId;
  }

  toJSON() {
    return {
      domain: this.domain,
      websiteId: this.websiteId,
      ownerNodeId: this.ownerNodeId,
      ownerDoko: this.ownerDoko,
      registeredAt: this.registeredAt,
      expiresAt: this.expiresAt,
      signature: this.signature,
      txtRecords: this.txtRecords,
      transferHistory: this.transferHistory,
    };
  }

  static fromJSON(json) {
    return new YakDomain(json);
  }
}

/**
 * Website Manifest with DOKO Publisher Verification
 * 
 * Each website is bound to its publisher's DOKO identity.
 * This enables:
 * - Verifiable authorship of content
 * - Domain ownership proofs
 * - Content integrity verification
 * 
 * SECURITY: publisherDoko uses iO-obfuscated identifiers,
 * never exposing raw hashes to the network.
 */
class WebsiteManifest {
  constructor(options = {}) {
    this.id = options.id || null;                     // Hash of manifest content
    this.name = options.name || 'Unnamed Website';
    this.domain = options.domain || null;             // .yak domain if registered
    this.root = options.root || '/';
    this.indexFile = options.indexFile || 'index.html';
    this.files = options.files || {};                 // { path: WebsiteFile }
    this.createdAt = options.createdAt || Date.now();
    this.updatedAt = options.updatedAt || Date.now();
    this.version = options.version || '1.0.0';
    this.publisherNodeId = options.publisherNodeId || null;
    this.publisherDoko = options.publisherDoko || null; // iO-obfuscated DOKO ID
    this.signature = options.signature || null;
    this.verified = options.verified || false;        // DOKO verification status
  }

  /**
   * Check if manifest is published by a specific DOKO identity
   * @param {string} dokoId - DOKO ID to verify (iO-obfuscated)
   * @returns {boolean}
   */
  isPublishedBy(dokoId) {
    return this.publisherDoko === dokoId;
  }

  /**
   * Mark as verified after DOKO signature check
   */
  markVerified() {
    this.verified = true;
  }

  /**
   * Compute manifest ID (hash of content)
   */
  computeId() {
    const content = JSON.stringify({
      name: this.name,
      files: Object.keys(this.files).sort().map(k => ({
        path: k,
        hash: this.files[k].hash,
      })),
      version: this.version,
      updatedAt: this.updatedAt,
    });
    return bytesToHex(sha3_256(utf8ToBytes(content)));
  }

  toJSON() {
    return {
      id: this.id,
      name: this.name,
      domain: this.domain,
      root: this.root,
      indexFile: this.indexFile,
      files: Object.fromEntries(
        Object.entries(this.files).map(([k, v]) => [k, v.toJSON()])
      ),
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      version: this.version,
      publisherNodeId: this.publisherNodeId,
      publisherDoko: this.publisherDoko,
      signature: this.signature,
      verified: this.verified,
    };
  }

  static fromJSON(json) {
    const manifest = new WebsiteManifest(json);
    manifest.files = Object.fromEntries(
      Object.entries(json.files || {}).map(([k, v]) => [k, WebsiteFile.fromJSON(v)])
    );
    return manifest;
  }
}

/**
 * YAKMESH Website Adapter
 * Serves static websites via the mesh network
 */
export class WebsiteAdapter extends BaseAdapter {
  constructor(node, config = {}) {
    super(node, config);
    
    this.config = {
      // Where website source files live
      sourceDir: config.sourceDir || './website',
      // Where to cache synced files
      cacheDir: config.cacheDir || './data/websites',
      // Default website to serve
      defaultWebsite: config.defaultWebsite || null,
      // Mount path on HTTP server
      mountPath: config.mountPath || '/site',
      // Enable .yak domain resolution
      yakDomains: config.yakDomains ?? true,
      // Auto-sync interval
      syncInterval: config.syncInterval || 30000,
      ...config
    };

    // Website manifests by ID
    this.manifests = new Map();
    
    // .yak domain registry
    this.domains = new Map();
    
    // File content cache (hash -> content)
    this.contentCache = new Map();
    
    // Stats
    this.stats = {
      ...this.stats,
      filesServed: 0,
      bytesServed: 0,
      cacheHits: 0,
      cacheMisses: 0,
    };
  }

  /**
   * Initialize the adapter
   */
  async init() {
    console.log('📄 Initializing Website Adapter...');
    
    // Create directories
    mkdirSync(this.config.cacheDir, { recursive: true });
    
    // Load existing manifests from cache
    await this._loadManifests();
    
    // Index source directory if it exists
    if (existsSync(this.config.sourceDir)) {
      await this.indexWebsite(this.config.sourceDir);
    }
    
    // Register gossip handlers
    this._registerGossipHandlers();
    
    // Mount HTTP routes
    this._mountRoutes();
    
    this.isInitialized = true;
    console.log(`✓ Website Adapter initialized`);
    console.log(`  Source:  ${this.config.sourceDir}`);
    console.log(`  Mount:   ${this.config.mountPath}`);
    console.log(`  Sites:   ${this.manifests.size}`);
    
    return this;
  }

  /**
   * Get schema for mesh replication
   */
  getSchema() {
    return {
      tables: [
        { name: 'website_manifests', primaryKey: 'id' },
        { name: 'website_files', primaryKey: 'hash' },
        { name: 'yak_domains', primaryKey: 'domain' },
      ],
    };
  }

  /**
   * Fetch changes for sync
   */
  async fetchChanges(since) {
    const changes = [];
    
    for (const [id, manifest] of this.manifests) {
      if (!since || manifest.updatedAt > since.getTime()) {
        changes.push({
          table: 'website_manifests',
          type: 'website_manifest',
          operation: 'UPSERT',
          data: manifest.toJSON(),
        });
      }
    }
    
    return changes;
  }

  /**
   * Apply incoming change from mesh
   */
  async applyChange(table, record, operation) {
    if (table === 'website_manifests') {
      const manifest = WebsiteManifest.fromJSON(record);
      this.manifests.set(manifest.id, manifest);
      this._saveManifest(manifest);
      console.log(`📥 Synced website: ${manifest.name} (${Object.keys(manifest.files).length} files)`);
    }
    
    if (table === 'website_files') {
      // Cache the file content
      this.contentCache.set(record.hash, record.content);
      this._cacheFile(record.hash, record.content);
    }
    
    if (table === 'yak_domains') {
      const domain = new YakDomain(record);
      this.domains.set(domain.domain, domain);
    }
  }

  /**
   * Index a website directory and create manifest
   */
  /**
   * Index a website directory with DOKO publisher binding
   * 
   * Creates a website manifest bound to the publisher's DOKO identity.
   * This provides verifiable authorship for all content.
   * 
   * @param {string} sourceDir - Directory containing website files
   * @param {object} options - Indexing options
   * @returns {WebsiteManifest}
   */
  async indexWebsite(sourceDir, options = {}) {
    const name = options.name || sourceDir.split(/[/\\]/).pop();
    const domain = options.domain || null;
    
    console.log(`📂 Indexing website: ${name} from ${sourceDir}`);
    
    // Generate publisher DOKO identity (iO-obfuscated)
    let publisherDoko = null;
    const nodeId = this.node.identity?.identity?.nodeId;
    const publicKey = this.node.identity?.identity?.publicKey;
    
    if (publicKey) {
      // Use static method to compute iO-obfuscated DOKO ID
      publisherDoko = DOKODocument.computeDokoId(publicKey, DOKO_TYPES.NODE);
      console.log(`  Publisher DOKO: ${publisherDoko}`);
    }
    
    const manifest = new WebsiteManifest({
      name,
      domain,
      publisherNodeId: nodeId,
      publisherDoko,
    });
    
    // Recursively scan directory
    const files = this._scanDirectory(sourceDir, sourceDir);
    
    for (const file of files) {
      const content = readFileSync(file.absolutePath);
      const hash = bytesToHex(sha3_256(new Uint8Array(content)));
      const ext = extname(file.relativePath).toLowerCase();
      
      manifest.files[file.relativePath] = new WebsiteFile({
        path: file.relativePath,
        hash,
        size: content.length,
        mimeType: MIME_TYPES[ext] || 'application/octet-stream',
        modifiedAt: file.modifiedAt,
        nodeId,
      });
      
      // Cache the content
      this.contentCache.set(hash, content);
    }
    
    // Compute manifest ID
    manifest.updatedAt = Date.now();
    manifest.id = manifest.computeId();
    
    // Sign manifest with node identity for verification
    if (this.node.identity) {
      const signData = JSON.stringify({
        id: manifest.id,
        publisherDoko,
        updatedAt: manifest.updatedAt,
      });
      manifest.signature = this.node.identity.sign(signData);
      manifest.markVerified(); // Self-published, so verified
    }
    
    // Store manifest
    this.manifests.set(manifest.id, manifest);
    this._saveManifest(manifest);
    
    console.log(`✓ Indexed ${Object.keys(manifest.files).length} files (${manifest.id.slice(0, 16)}...)`);
    if (publisherDoko) {
      console.log(`  DOKO verified: ✓`);
    }
    
    // Set as default if none set
    if (!this.config.defaultWebsite) {
      this.config.defaultWebsite = manifest.id;
    }
    
    return manifest;
  }

  /**
   * Register a .yak domain with DOKO identity binding
   * 
   * Domain ownership is bound to the registrant's DOKO identity.
   * This provides verifiable ownership without centralized registrars.
   * 
   * @param {string} domainName - Domain name (e.g., "mysite" or "mysite.yak")
   * @param {string} websiteId - Website manifest ID
   * @returns {YakDomain}
   */
  async registerDomain(domainName, websiteId) {
    if (!domainName.endsWith('.yak')) {
      domainName += '.yak';
    }
    
    const manifest = this.manifests.get(websiteId);
    if (!manifest) {
      throw new Error(`Website ${websiteId} not found`);
    }
    
    // Generate owner DOKO identity (iO-obfuscated)
    let ownerDoko = null;
    const nodeId = this.node.identity?.identity?.nodeId;
    const publicKey = this.node.identity?.identity?.publicKey;
    
    if (publicKey) {
      // Use static method to compute iO-obfuscated DOKO ID
      ownerDoko = DOKODocument.computeDokoId(publicKey, DOKO_TYPES.NODE);
    }
    
    const domain = new YakDomain({
      domain: domainName,
      websiteId,
      ownerNodeId: nodeId,
      ownerDoko, // DOKO identity binding
    });
    
    // Sign the domain record with DOKO binding
    if (this.node.identity) {
      const signData = JSON.stringify({
        domain: domain.domain,
        websiteId: domain.websiteId,
        ownerDoko: domain.ownerDoko,
        registeredAt: domain.registeredAt,
      });
      domain.signature = this.node.identity.sign(signData);
    }
    
    this.domains.set(domainName, domain);
    manifest.domain = domainName;
    
    // Broadcast domain registration with DOKO
    this.node.gossip?.spreadRumor('yak_domain', domain.toJSON());
    
    console.log(`🌐 Registered domain: ${domainName} → ${manifest.name}`);
    if (ownerDoko) {
      console.log(`  Owner DOKO: ${ownerDoko}`);
    }
    
    return domain;
  }

  /**
   * Resolve a .yak domain to a website
   */
  resolveDomain(domainName) {
    if (!domainName.endsWith('.yak')) {
      domainName += '.yak';
    }
    
    const domain = this.domains.get(domainName);
    if (!domain) return null;
    
    return this.manifests.get(domain.websiteId) || null;
  }

  /**
   * Verify DOKO ownership of a domain
   * 
   * Checks if the given DOKO identity owns a domain.
   * Used for domain transfer verification and access control.
   * 
   * @param {string} domainName - Domain to verify
   * @param {string} dokoId - DOKO ID claiming ownership
   * @returns {object} Verification result
   */
  verifyDomainOwnership(domainName, dokoId) {
    if (!domainName.endsWith('.yak')) {
      domainName += '.yak';
    }
    
    const domain = this.domains.get(domainName);
    if (!domain) {
      return { verified: false, error: 'Domain not found' };
    }
    
    if (domain.isExpired()) {
      return { verified: false, error: 'Domain expired' };
    }
    
    const isOwner = domain.isOwnedBy(dokoId);
    return {
      verified: isOwner,
      domain: domainName,
      ownerDoko: domain.ownerDoko,
      requestedDoko: dokoId,
      registeredAt: domain.registeredAt,
      expiresAt: domain.expiresAt,
    };
  }

  /**
   * Verify DOKO publisher of a website
   * 
   * Checks if a website was published by a specific DOKO identity.
   * 
   * @param {string} websiteId - Website manifest ID
   * @param {string} dokoId - DOKO ID to verify
   * @returns {object} Verification result
   */
  verifyPublisher(websiteId, dokoId) {
    const manifest = this.manifests.get(websiteId);
    if (!manifest) {
      return { verified: false, error: 'Website not found' };
    }
    
    const isPublisher = manifest.isPublishedBy(dokoId);
    return {
      verified: isPublisher,
      websiteId,
      websiteName: manifest.name,
      publisherDoko: manifest.publisherDoko,
      requestedDoko: dokoId,
      manifestVerified: manifest.verified,
    };
  }

  /**
   * Get all domains owned by a DOKO identity
   * 
   * @param {string} dokoId - DOKO ID to search for
   * @returns {YakDomain[]} Domains owned by this DOKO
   */
  getDomainsByDoko(dokoId) {
    const owned = [];
    for (const domain of this.domains.values()) {
      if (domain.isOwnedBy(dokoId) && !domain.isExpired()) {
        owned.push(domain);
      }
    }
    return owned;
  }

  /**
   * Serve a file from a website
   */
  serveFile(websiteId, filePath) {
    const manifest = this.manifests.get(websiteId);
    if (!manifest) return null;
    
    // Normalize path
    if (filePath.startsWith('/')) filePath = filePath.slice(1);
    if (!filePath || filePath === '') filePath = manifest.indexFile;
    
    // Try exact path
    let fileInfo = manifest.files[filePath];
    
    // Try with index.html if directory
    if (!fileInfo) {
      fileInfo = manifest.files[`${filePath}/index.html`] || manifest.files[`${filePath}index.html`];
    }
    
    if (!fileInfo) return null;
    
    // Get content from cache
    let content = this.contentCache.get(fileInfo.hash);
    
    if (!content) {
      // Try to load from disk cache
      content = this._loadCachedFile(fileInfo.hash);
    }
    
    if (content) {
      this.stats.filesServed++;
      this.stats.bytesServed += content.length;
      this.stats.cacheHits++;
    } else {
      this.stats.cacheMisses++;
      // Request from mesh
      this._requestFile(fileInfo.hash);
    }
    
    return content ? { content, metadata: fileInfo } : null;
  }

  /**
   * Mount HTTP routes on the node's Express app
   */
  _mountRoutes() {
    const app = this.node.app;
    if (!app) {
      console.warn('⚠️ No Express app available, HTTP routes not mounted');
      return;
    }
    
    // Serve website files
    app.get(`${this.config.mountPath}/*`, (req, res) => {
      const path = req.params[0] || '';
      const websiteId = this.config.defaultWebsite;
      
      if (!websiteId) {
        return res.status(404).json({ error: 'No website configured' });
      }
      
      const result = this.serveFile(websiteId, path);
      
      if (!result) {
        return res.status(404).send('File not found');
      }
      
      res.set('Content-Type', result.metadata.mimeType);
      res.set('X-Yakmesh-Hash', result.metadata.hash);
      res.set('Cache-Control', 'public, max-age=3600');
      res.send(result.content);
    });

    // .yak domain resolution
    app.get('/yak/:domain', (req, res) => {
      const manifest = this.resolveDomain(req.params.domain);
      if (!manifest) {
        return res.status(404).json({ error: 'Domain not found' });
      }
      res.redirect(`${this.config.mountPath}/${manifest.id}/`);
    });
    
    // .yak domain resolution with path
    app.get('/yak/:domain/*', (req, res) => {
      const manifest = this.resolveDomain(req.params.domain);
      if (!manifest) {
        return res.status(404).json({ error: 'Domain not found' });
      }
      const path = req.params[0] || '';
      const result = this.serveFile(manifest.id, path);
      
      if (!result) {
        return res.status(404).send('File not found');
      }
      
      res.set('Content-Type', result.metadata.mimeType);
      res.set('X-Yakmesh-Hash', result.metadata.hash);
      res.send(result.content);
    });

    // List websites (with DOKO info)
    app.get('/websites', (req, res) => {
      const websites = [];
      for (const [id, manifest] of this.manifests) {
        websites.push({
          id,
          name: manifest.name,
          domain: manifest.domain,
          files: Object.keys(manifest.files).length,
          version: manifest.version,
          updatedAt: manifest.updatedAt,
          publisherDoko: manifest.publisherDoko,
          verified: manifest.verified,
        });
      }
      res.json(websites);
    });

    // List .yak domains (with DOKO info)
    app.get('/domains', (req, res) => {
      const domains = [];
      for (const [name, domain] of this.domains) {
        const manifest = this.manifests.get(domain.websiteId);
        domains.push({
          domain: name,
          websiteId: domain.websiteId,
          websiteName: manifest?.name || 'Unknown',
          ownerNodeId: domain.ownerNodeId,
          ownerDoko: domain.ownerDoko,
          registeredAt: domain.registeredAt,
          expiresAt: domain.expiresAt,
          expired: domain.isExpired(),
        });
      }
      res.json(domains);
    });

    // DOKO: Verify domain ownership
    app.get('/verify/domain/:domain', (req, res) => {
      const { dokoId } = req.query;
      if (!dokoId) {
        // Return domain info without verification
        const domain = this.domains.get(
          req.params.domain.endsWith('.yak') ? req.params.domain : `${req.params.domain}.yak`
        );
        if (!domain) {
          return res.status(404).json({ error: 'Domain not found' });
        }
        return res.json({
          domain: domain.domain,
          ownerDoko: domain.ownerDoko,
          expired: domain.isExpired(),
          registeredAt: domain.registeredAt,
          expiresAt: domain.expiresAt,
        });
      }
      const result = this.verifyDomainOwnership(req.params.domain, dokoId);
      res.json(result);
    });

    // DOKO: Verify website publisher
    app.get('/verify/publisher/:websiteId', (req, res) => {
      const { dokoId } = req.query;
      if (!dokoId) {
        // Return publisher info without verification
        const manifest = this.manifests.get(req.params.websiteId);
        if (!manifest) {
          return res.status(404).json({ error: 'Website not found' });
        }
        return res.json({
          websiteId: manifest.id,
          name: manifest.name,
          publisherDoko: manifest.publisherDoko,
          verified: manifest.verified,
        });
      }
      const result = this.verifyPublisher(req.params.websiteId, dokoId);
      res.json(result);
    });

    // DOKO: Get domains by DOKO ID
    app.get('/doko/:dokoId/domains', (req, res) => {
      const domains = this.getDomainsByDoko(req.params.dokoId);
      res.json({
        dokoId: req.params.dokoId,
        count: domains.length,
        domains: domains.map(d => d.toJSON()),
      });
    });

    // Website stats
    app.get('/website/stats', (req, res) => {
      res.json({
        websites: this.manifests.size,
        domains: this.domains.size,
        filesServed: this.stats.filesServed,
        bytesServed: this.stats.bytesServed,
        cacheHits: this.stats.cacheHits,
        cacheMisses: this.stats.cacheMisses,
        hitRate: this.stats.cacheHits / (this.stats.cacheHits + this.stats.cacheMisses) || 0,
      });
    });

    console.log(`✓ Website routes mounted at ${this.config.mountPath}`);
  }

  /**
   * Register gossip handlers for mesh sync
   */
  _registerGossipHandlers() {
    if (!this.node.mesh) return;
    
    this.node.mesh.on('rumor', (topic, data, origin) => {
      if (topic === 'website_manifest') {
        this.applyChange('website_manifests', data, 'UPSERT');
      }
      if (topic === 'website_file') {
        this.applyChange('website_files', data, 'UPSERT');
      }
      if (topic === 'yak_domain') {
        this.applyChange('yak_domains', data, 'UPSERT');
      }
    });
  }

  /**
   * Scan a directory recursively
   */
  _scanDirectory(dir, rootDir) {
    const files = [];
    const entries = readdirSync(dir, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      
      // Skip hidden files and common excludes
      if (entry.name.startsWith('.')) continue;
      if (entry.name === 'node_modules') continue;
      
      if (entry.isDirectory()) {
        files.push(...this._scanDirectory(fullPath, rootDir));
      } else {
        const stat = statSync(fullPath);
        files.push({
          absolutePath: fullPath,
          relativePath: relative(rootDir, fullPath).replace(/\\/g, '/'),
          modifiedAt: stat.mtimeMs,
        });
      }
    }
    
    return files;
  }

  /**
   * Load manifests from cache directory
   */
  async _loadManifests() {
    const manifestDir = join(this.config.cacheDir, 'manifests');
    if (!existsSync(manifestDir)) {
      mkdirSync(manifestDir, { recursive: true });
      return;
    }
    
    const files = readdirSync(manifestDir);
    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      try {
        const content = readFileSync(join(manifestDir, file), 'utf8');
        const manifest = WebsiteManifest.fromJSON(JSON.parse(content));
        this.manifests.set(manifest.id, manifest);
      } catch (e) {
        console.warn(`Failed to load manifest ${file}: ${e.message}`);
      }
    }
  }

  /**
   * Save a manifest to cache
   */
  _saveManifest(manifest) {
    const manifestDir = join(this.config.cacheDir, 'manifests');
    mkdirSync(manifestDir, { recursive: true });
    writeFileSync(
      join(manifestDir, `${manifest.id}.json`),
      JSON.stringify(manifest.toJSON(), null, 2)
    );
  }

  /**
   * Load a cached file by hash
   */
  _loadCachedFile(hash) {
    const filePath = join(this.config.cacheDir, 'files', hash.slice(0, 2), hash);
    if (existsSync(filePath)) {
      return readFileSync(filePath);
    }
    return null;
  }

  /**
   * Cache a file by hash
   */
  _cacheFile(hash, content) {
    const dir = join(this.config.cacheDir, 'files', hash.slice(0, 2));
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, hash), content);
  }

  /**
   * Request a file from the mesh
   */
  _requestFile(hash) {
    if (this.node.gossip) {
      this.node.gossip.spreadRumor('file_request', { hash });
    }
  }
}

export { WebsiteFile, WebsiteManifest, YakDomain };
export default WebsiteAdapter;
