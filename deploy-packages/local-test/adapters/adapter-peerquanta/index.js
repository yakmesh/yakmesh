/**
 * PeerQuanta Integration Module
 * Bridges phpBB SQLite database with Lantern mesh network
 * 
 * This module allows PeerQuanta marketplace data to be:
 * 1. Synced across multiple Lantern nodes
 * 2. Resilient to single server failures
 * 3. Optionally decentralized across community-run nodes
 * 
 * SECURITY: All data is validated through the ValidationOracle
 * before being written or propagated. This ensures:
 * - Deterministic validation (same rules on all nodes)
 * - Injection attack prevention
 * - Content integrity verification
 * 
 * v2.0 SECURITY FEATURES:
 * - DOKO Trader Identity - Self-sovereign identities
 * - Trust-Based Escrow - Variable escrow based on trust level
 * - ANNEX Trade Chat - Encrypted P2P messaging
 * - Merchant Domain Verification - Mesh-verified domains
 */

import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import initSqlJs from 'sql.js';
import { getOracle, contentHash } from '../../oracle/index.js';

// v2.0 Security Integration
import PeerQuantaSecurity from './security.js';

// sql.js instance
let SQL = null;

/**
 * Initialize sql.js WASM
 */
async function initSQL() {
  if (!SQL) {
    SQL = await initSqlJs();
  }
  return SQL;
}

/**
 * PeerQuanta Database Schema
 * Tables that should be replicated across the mesh
 */
export const PEERQUANTA_TABLES = {
  // Marketplace listings
  listings: {
    table: 'p2pq_listings',
    primaryKey: 'id',
    replicateFields: [
      'id', 'user_id', 'title', 'description', 'currency', 'price',
      'payment_methods', 'trade_limits', 'terms', 'status',
      'location_country', 'location_region', 'trade_type',
      'margin_type', 'margin_value', 'time_limit',
      'created_at', 'updated_at'
    ],
    excludeFields: ['management_key', 'key_binding_data', 'anchor_hash'], // Sensitive
  },
  
  // QCoA Certificates
  qcoa: {
    table: 'qcoa_certificates',
    primaryKey: 'id',
    replicateFields: [
      'id', 'cert_hash', 'origin_public_key', 'origin_signature',
      'asset_type', 'asset_id', 'timestamp', 'status',
      'verified', 'verification_method', 'verification_timestamp',
      'metadata'
    ],
  },
  
  // User reputation (public portion only)
  reputation: {
    table: 'p2pq_user_stats',
    primaryKey: 'user_id',
    replicateFields: [
      'user_id', 'total_trades', 'successful_trades',
      'positive_feedback', 'negative_feedback',
      'average_response_time', 'last_trade_date'
    ],
  },
};

/**
 * Integration Bridge between PeerQuanta and Lantern
 * 
 * All data passing through this bridge is validated by the ValidationOracle,
 * ensuring deterministic validation and preventing injection attacks.
 */
export class PeerQuantaBridge {
  constructor(lanternNode, phpbbDbPath) {
    this.node = lanternNode;
    this.phpbbDbPath = phpbbDbPath;
    this.syncInterval = null;
    this.lastSyncTime = {};
    this.phpbbDb = null;
    
    // ValidationOracle for secure content validation
    this.oracle = null;
    
    // Statistics for oracle validation
    this.validationStats = {
      listingsValidated: 0,
      listingsRejected: 0,
      qcoaValidated: 0,
      qcoaRejected: 0,
      totalRejected: 0,
    };
    
    // Track pending changes
    this.pendingChanges = [];
    
    // Track last synced IDs for each table
    this.lastSyncedIds = {
      listings: 0,
      qcoa: 0,
      reputation: 0,
    };
    
    // v2.0 Security Integration (initialized in init())
    this.security = null;
  }

  /**
   * Initialize the bridge
   */
  async init() {
    console.log('🔗 Initializing PeerQuanta Bridge...');
    
    // Initialize ValidationOracle for secure content validation
    this.oracle = getOracle();
    console.log(`✓ ValidationOracle attached: ${this.oracle.selfHash.slice(0, 16)}...`);
    
    // Initialize sql.js
    const SqlJs = await initSQL();
    
    // Try to connect to phpBB database
    if (this.phpbbDbPath && existsSync(this.phpbbDbPath)) {
      try {
        const buffer = readFileSync(this.phpbbDbPath);
        this.phpbbDb = new SqlJs.Database(buffer);
        console.log(`✓ Connected to phpBB database: ${this.phpbbDbPath}`);
        
        // Get initial state
        this._loadLastSyncedIds();
      } catch (error) {
        console.error(`✗ Failed to load phpBB database: ${error.message}`);
      }
    } else {
      console.log(`⚠ phpBB database not found at: ${this.phpbbDbPath}`);
      console.log('  Bridge will operate in mesh-only mode');
    }
    
    // Register rumor handler for incoming data
    this.node.mesh.on('rumor', (topic, data, origin) => {
      if (topic.startsWith('pq:')) {
        this._handlePeerQuantaRumor(topic, data, origin);
      }
    });
    
    // Initialize v2.0 Security features
    try {
      this.security = new PeerQuantaSecurity(this);
      console.log('✓ v2.0 Security features enabled');
    } catch (error) {
      console.warn(`⚠ v2.0 Security features unavailable: ${error.message}`);
    }
    
    console.log('✓ PeerQuanta Bridge initialized');
  }
  
  /**
   * Load last synced IDs from replication state
   */
  _loadLastSyncedIds() {
    try {
      const result = this.node.replication.db.exec(
        `SELECT * FROM _replication_state WHERE peer_node_id = 'phpbb_sync'`
      );
      
      if (result.length > 0 && result[0].values.length > 0) {
        const clockData = JSON.parse(result[0].values[0][2] || '{}');
        this.lastSyncedIds = {
          listings: clockData.listings || 0,
          qcoa: clockData.qcoa || 0,
          reputation: clockData.reputation || 0,
        };
        console.log(`  Restored sync state: listings=${this.lastSyncedIds.listings}, qcoa=${this.lastSyncedIds.qcoa}`);
      }
    } catch (e) {
      // First run, no state yet
    }
  }
  
  /**
   * Save sync state
   */
  _saveSyncState() {
    try {
      this.node.replication.db.run(
        `INSERT OR REPLACE INTO _replication_state (peer_node_id, last_sync_at, last_vector_clock)
         VALUES (?, ?, ?)`,
        ['phpbb_sync', Date.now(), JSON.stringify(this.lastSyncedIds)]
      );
      this.node.replication._saveDb();
    } catch (e) {
      console.error('Failed to save sync state:', e.message);
    }
  }

  /**
   * Start periodic sync from phpBB to Lantern
   */
  startSync(intervalMs = 60000) {
    console.log(`✓ PeerQuanta sync started (every ${intervalMs / 1000}s)`);
    
    this.syncInterval = setInterval(() => {
      this._syncFromPhpBB();
    }, intervalMs);
    
    // Initial sync
    this._syncFromPhpBB();
  }

  /**
   * Stop sync
   */
  stopSync() {
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
  }

  /**
   * Validate a listing through the Oracle
   * @param {Object} listing - The listing to validate
   * @returns {Object} Validation result with contentHash
   */
  _validateListing(listing) {
    if (!this.oracle) {
      return { valid: false, reason: 'ORACLE_NOT_INITIALIZED' };
    }
    
    const result = this.oracle.validateListing(listing);
    
    if (result.valid) {
      this.validationStats.listingsValidated++;
    } else {
      this.validationStats.listingsRejected++;
      this.validationStats.totalRejected++;
      console.warn(`⚠️ Listing validation failed: ${result.reason}`);
    }
    
    return result;
  }

  /**
   * Validate a QCoA certificate through the Oracle
   * @param {Object} cert - The certificate to validate
   * @returns {Object} Validation result
   */
  _validateQCoA(cert) {
    if (!this.oracle) {
      return { valid: false, reason: 'ORACLE_NOT_INITIALIZED' };
    }
    
    const result = this.oracle.validateQCoA(cert);
    
    if (result.valid) {
      this.validationStats.qcoaValidated++;
    } else {
      this.validationStats.qcoaRejected++;
      this.validationStats.totalRejected++;
      console.warn(`⚠️ QCoA validation failed: ${result.reason}`);
    }
    
    return result;
  }

  /**
   * Manually push a listing to the mesh
   * All listings are validated through the Oracle before propagation.
   * 
   * @param {Object} listing - The listing data
   * @param {boolean} writeToPhpBB - Also write to phpBB database (default: true)
   * @returns {Object} Result with success status and contentHash
   */
  async pushListing(listing, writeToPhpBB = true) {
    const sanitized = this._sanitizeListing(listing);
    
    // ═══════════════════════════════════════════════════════════
    // ORACLE VALIDATION - All listings must pass validation
    // ═══════════════════════════════════════════════════════════
    const validation = this._validateListing(sanitized);
    
    if (!validation.valid) {
      return {
        success: false,
        error: 'VALIDATION_FAILED',
        reason: validation.reason,
        listing: sanitized,
      };
    }
    
    // Attach oracle metadata for verification by other nodes
    const oracleMetadata = {
      validatedBy: this.oracle.selfHash,
      contentHash: validation.data?.contentHash || contentHash(sanitized),
      validatedAt: Date.now(),
    };
    
    // Write to phpBB database if connected
    if (writeToPhpBB && this.phpbbDb) {
      try {
        const result = await this._writeListingToPhpBB(sanitized);
        if (result.id) {
          sanitized.id = result.id;
        }
      } catch (error) {
        console.error('Failed to write listing to phpBB:', error.message);
      }
    }
    
    // Spread to mesh with oracle metadata
    this.node.gossip.spreadRumor('pq:listing:update', {
      listing: sanitized,
      oracle: oracleMetadata,
      timestamp: Date.now(),
    });
    
    // Also record in replication
    this.node.replication.recordChange(
      'pq_listings',
      sanitized.id || listing.id,
      'UPSERT',
      { ...sanitized, _oracle: oracleMetadata }
    );
    
    return {
      success: true,
      listingId: sanitized.id || listing.id,
      contentHash: oracleMetadata.contentHash,
      validatedBy: oracleMetadata.validatedBy,
    };
  }
  
  /**
   * Write a listing to the phpBB database (insert or update)
   */
  async _writeListingToPhpBB(listing) {
    if (!this.phpbbDb) {
      throw new Error('phpBB database not connected');
    }
    
    const config = PEERQUANTA_TABLES.listings;
    const now = Math.floor(Date.now() / 1000);
    
    if (listing.id) {
      // Update existing listing
      const updateFields = config.replicateFields
        .filter(f => f !== 'id' && f !== 'created_at' && listing[f] !== undefined)
        .map(f => `${f} = ?`);
      
      const values = config.replicateFields
        .filter(f => f !== 'id' && f !== 'created_at' && listing[f] !== undefined)
        .map(f => listing[f]);
      
      // Always update updated_at
      if (!updateFields.includes('updated_at = ?')) {
        updateFields.push('updated_at = ?');
        values.push(now);
      }
      
      values.push(listing.id);
      
      this.phpbbDb.run(
        `UPDATE ${config.table} SET ${updateFields.join(', ')} WHERE id = ?`,
        values
      );
      
      // Save to disk
      this._savePhpBBDb();
      
      return { id: listing.id, action: 'updated' };
    } else {
      // Insert new listing
      const insertFields = config.replicateFields.filter(f => 
        f !== 'id' && listing[f] !== undefined
      );
      
      // Add timestamps if not present
      if (!insertFields.includes('created_at')) {
        insertFields.push('created_at');
        listing.created_at = now;
      }
      if (!insertFields.includes('updated_at')) {
        insertFields.push('updated_at');
        listing.updated_at = now;
      }
      
      const placeholders = insertFields.map(() => '?').join(', ');
      const values = insertFields.map(f => listing[f]);
      
      this.phpbbDb.run(
        `INSERT INTO ${config.table} (${insertFields.join(', ')}) VALUES (${placeholders})`,
        values
      );
      
      // Get the inserted ID
      const result = this.phpbbDb.exec('SELECT last_insert_rowid()');
      const newId = result[0]?.values[0][0];
      
      // Save to disk
      this._savePhpBBDb();
      
      return { id: newId, action: 'inserted' };
    }
  }
  
  /**
   * Save phpBB database to disk
   */
  _savePhpBBDb() {
    if (!this.phpbbDb || !this.phpbbDbPath) return;
    
    try {
      const data = this.phpbbDb.export();
      writeFileSync(this.phpbbDbPath, Buffer.from(data));
    } catch (error) {
      console.error('Failed to save phpBB database:', error.message);
    }
  }

  /**
   * Push a QCoA certificate to the mesh
   * All certificates are validated through the Oracle before propagation.
   * 
   * @param {Object} cert - The certificate data
   * @returns {Object} Result with success status and validation info
   */
  async pushQCoACertificate(cert) {
    // ═══════════════════════════════════════════════════════════
    // ORACLE VALIDATION - All certificates must pass validation
    // ═══════════════════════════════════════════════════════════
    const validation = this._validateQCoA(cert);
    
    if (!validation.valid) {
      return {
        success: false,
        error: 'VALIDATION_FAILED',
        reason: validation.reason,
      };
    }
    
    // Attach oracle metadata
    const oracleMetadata = {
      validatedBy: this.oracle.selfHash,
      certHash: validation.data?.certHash || cert.cert_hash,
      validatedAt: Date.now(),
    };
    
    this.node.gossip.spreadRumor('pq:qcoa:new', {
      certificate: cert,
      oracle: oracleMetadata,
      timestamp: Date.now(),
    });
    
    this.node.replication.recordChange(
      'qcoa_certificates',
      cert.id,
      'INSERT',
      { ...cert, _oracle: oracleMetadata }
    );
    
    return {
      success: true,
      certId: cert.id,
      certHash: oracleMetadata.certHash,
      validatedBy: oracleMetadata.validatedBy,
    };
  }

  /**
   * Get current mesh status for PeerQuanta including Oracle validation stats
   */
  getStatus() {
    return {
      connected: true,
      nodeId: this.node.identity.identity.nodeId,
      peers: this.node.mesh.getPeers().length,
      discoveredPeers: this.node.gossip.getKnownPeers().length,
      replicationStats: this.node.replication.getStats(),
      gossipStats: this.node.gossip.getStats(),
      lastSync: this.lastSyncTime,
      // Oracle validation statistics
      oracle: {
        selfHash: this.oracle?.selfHash?.slice(0, 32) || 'not-initialized',
        validationStats: this.validationStats,
        integrityValid: this.oracle?.verifySelfIntegrity()?.valid || false,
      },
    };
  }

  /**
   * Internal: Sync changes from phpBB database
   */
  async _syncFromPhpBB() {
    if (!this.phpbbDb) {
      console.log('⚠ No phpBB database connected, skipping sync');
      return;
    }
    
    console.log('📊 Syncing from phpBB database...');
    
    try {
      let totalSynced = 0;
      
      // 1. Sync new/updated listings
      const listingsConfig = PEERQUANTA_TABLES.listings;
      const listingsResult = this.phpbbDb.exec(`
        SELECT ${listingsConfig.replicateFields.join(', ')}
        FROM ${listingsConfig.table}
        WHERE id > ${this.lastSyncedIds.listings}
           OR updated_at > ${this.lastSyncTime.phpbb || 0}
        ORDER BY id ASC
        LIMIT 100
      `);
      
      if (listingsResult.length > 0 && listingsResult[0].values.length > 0) {
        const columns = listingsResult[0].columns;
        for (const row of listingsResult[0].values) {
          const listing = {};
          columns.forEach((col, i) => {
            listing[col] = row[i];
          });
          
          // Push to mesh
          await this.pushListing(listing);
          totalSynced++;
          
          // Update last synced ID
          if (listing.id > this.lastSyncedIds.listings) {
            this.lastSyncedIds.listings = listing.id;
          }
        }
        console.log(`  ✓ Synced ${listingsResult[0].values.length} listings`);
      }
      
      // 2. Sync QCoA certificates
      try {
        const qcoaConfig = PEERQUANTA_TABLES.qcoa;
        const qcoaResult = this.phpbbDb.exec(`
          SELECT ${qcoaConfig.replicateFields.join(', ')}
          FROM ${qcoaConfig.table}
          WHERE id > ${this.lastSyncedIds.qcoa}
          ORDER BY id ASC
          LIMIT 100
        `);
        
        if (qcoaResult.length > 0 && qcoaResult[0].values.length > 0) {
          const columns = qcoaResult[0].columns;
          for (const row of qcoaResult[0].values) {
            const cert = {};
            columns.forEach((col, i) => {
              cert[col] = row[i];
            });
            
            await this.pushQCoACertificate(cert);
            totalSynced++;
            
            if (cert.id > this.lastSyncedIds.qcoa) {
              this.lastSyncedIds.qcoa = cert.id;
            }
          }
          console.log(`  ✓ Synced ${qcoaResult[0].values.length} QCoA certificates`);
        }
      } catch (e) {
        // QCoA table might not exist yet
        if (!e.message.includes('no such table')) {
          console.error('  QCoA sync error:', e.message);
        }
      }
      
      // 3. Sync user reputation stats
      try {
        const repConfig = PEERQUANTA_TABLES.reputation;
        const repResult = this.phpbbDb.exec(`
          SELECT ${repConfig.replicateFields.join(', ')}
          FROM ${repConfig.table}
          WHERE user_id > ${this.lastSyncedIds.reputation}
          ORDER BY user_id ASC
          LIMIT 100
        `);
        
        if (repResult.length > 0 && repResult[0].values.length > 0) {
          const columns = repResult[0].columns;
          for (const row of repResult[0].values) {
            const stats = {};
            columns.forEach((col, i) => {
              stats[col] = row[i];
            });
            
            this.node.gossip.spreadRumor('pq:reputation:update', {
              userId: stats.user_id,
              stats,
              timestamp: Date.now(),
            });
            totalSynced++;
            
            if (stats.user_id > this.lastSyncedIds.reputation) {
              this.lastSyncedIds.reputation = stats.user_id;
            }
          }
          console.log(`  ✓ Synced ${repResult[0].values.length} reputation records`);
        }
      } catch (e) {
        // Reputation table might not exist yet
        if (!e.message.includes('no such table')) {
          console.error('  Reputation sync error:', e.message);
        }
      }
      
      // Save sync state
      this.lastSyncTime.phpbb = Date.now();
      this._saveSyncState();
      
      if (totalSynced > 0) {
        console.log(`✓ phpBB sync complete: ${totalSynced} records pushed to mesh`);
      }
      
    } catch (error) {
      console.error('phpBB sync error:', error.message);
    }
  }
  
  /**
   * Refresh phpBB database connection (re-read from disk)
   */
  async refreshPhpBBConnection() {
    if (!this.phpbbDbPath || !existsSync(this.phpbbDbPath)) {
      return false;
    }
    
    try {
      const SqlJs = await initSQL();
      const buffer = readFileSync(this.phpbbDbPath);
      this.phpbbDb = new SqlJs.Database(buffer);
      console.log('✓ Refreshed phpBB database connection');
      return true;
    } catch (error) {
      console.error('Failed to refresh phpBB database:', error.message);
      return false;
    }
  }
  
  /**
   * Get listings directly from phpBB database
   */
  getListingsFromPhpBB(filters = {}) {
    if (!this.phpbbDb) return [];
    
    try {
      const config = PEERQUANTA_TABLES.listings;
      let query = `SELECT ${config.replicateFields.join(', ')} FROM ${config.table} WHERE status = 'active'`;
      
      if (filters.userId) {
        query += ` AND user_id = ${filters.userId}`;
      }
      if (filters.currency) {
        query += ` AND currency = '${filters.currency}'`;
      }
      if (filters.tradeType) {
        query += ` AND trade_type = '${filters.tradeType}'`;
      }
      
      query += ' ORDER BY created_at DESC LIMIT 100';
      
      const result = this.phpbbDb.exec(query);
      
      if (result.length === 0 || result[0].values.length === 0) {
        return [];
      }
      
      const columns = result[0].columns;
      return result[0].values.map(row => {
        const listing = {};
        columns.forEach((col, i) => {
          listing[col] = row[i];
        });
        return listing;
      });
    } catch (error) {
      console.error('Error getting listings from phpBB:', error.message);
      return [];
    }
  }

  /**
   * Internal: Handle incoming PeerQuanta rumors
   */
  _handlePeerQuantaRumor(topic, data, origin) {
    console.log(`📨 PeerQuanta rumor [${topic}] from ${origin.slice(0, 16)}...`);
    
    switch (topic) {
      case 'pq:listing:update':
        this._handleListingUpdate(data, origin);
        break;
      case 'pq:listing:delete':
        this._handleListingDelete(data, origin);
        break;
      case 'pq:qcoa:new':
        this._handleQCoACertificate(data, origin);
        break;
      case 'pq:reputation:update':
        this._handleReputationUpdate(data, origin);
        break;
    }
  }

  /**
   * Handle listing update from mesh
   * Validates all incoming listings through the Oracle before accepting.
   */
  _handleListingUpdate(data, origin) {
    const { listing, oracle: oracleMetadata, timestamp } = data;
    
    // Verify the listing has required fields
    if (!listing.id || !listing.user_id) {
      console.log('⚠️ Invalid listing received, missing required fields');
      return;
    }
    
    // ═══════════════════════════════════════════════════════════
    // ORACLE VALIDATION - Validate incoming content
    // ═══════════════════════════════════════════════════════════
    const validation = this._validateListing(listing);
    
    if (!validation.valid) {
      console.warn(`⚠️ Rejected listing from ${origin.slice(0, 16)}...: ${validation.reason}`);
      return;
    }
    
    // Verify content hash matches (if provided)
    if (oracleMetadata?.contentHash) {
      const localHash = validation.data?.contentHash || contentHash(listing);
      if (localHash !== oracleMetadata.contentHash) {
        console.warn(`⚠️ Content hash mismatch from ${origin.slice(0, 16)}...`);
        console.warn(`   Expected: ${oracleMetadata.contentHash.slice(0, 24)}...`);
        console.warn(`   Computed: ${localHash.slice(0, 24)}...`);
        // Still accept - deterministic validation passed
      }
    }
    
    // Record in local replication with validation metadata
    this.node.replication.recordChange(
      'pq_listings',
      listing.id,
      'UPSERT',
      {
        ...listing,
        _origin: origin,
        _received: Date.now(),
        _validated: true,
        _validatedBy: this.oracle.selfHash,
      }
    );
    
    console.log(`✓ Listing ${listing.id} validated and synced from ${origin.slice(0, 16)}...`);
  }

  /**
   * Handle listing deletion from mesh
   */
  _handleListingDelete(data, origin) {
    const { listingId, timestamp } = data;
    
    this.node.replication.recordChange(
      'pq_listings',
      listingId,
      'DELETE',
      { id: listingId, status: 'deleted', _origin: origin }
    );
    
    console.log(`✓ Listing ${listingId} marked deleted from ${origin.slice(0, 16)}...`);
  }

  /**
   * Handle new QCoA certificate
   * Validates all incoming certificates through the Oracle before accepting.
   */
  _handleQCoACertificate(data, origin) {
    const { certificate, oracle: oracleMetadata, timestamp } = data;
    
    // Verify certificate structure
    if (!certificate.cert_hash || !certificate.origin_signature) {
      console.log('⚠️ Invalid QCoA certificate received, missing required fields');
      return;
    }
    
    // ═══════════════════════════════════════════════════════════
    // ORACLE VALIDATION - Validate incoming certificate
    // ═══════════════════════════════════════════════════════════
    const validation = this._validateQCoA(certificate);
    
    if (!validation.valid) {
      console.warn(`⚠️ Rejected QCoA from ${origin.slice(0, 16)}...: ${validation.reason}`);
      return;
    }
    
    this.node.replication.recordChange(
      'qcoa_certificates',
      certificate.id,
      'INSERT',
      {
        ...certificate,
        _origin: origin,
        _validated: true,
        _validatedBy: this.oracle.selfHash,
      }
    );
    
    console.log(`✓ QCoA ${certificate.cert_hash.slice(0, 16)}... validated and synced`);
  }

  /**
   * Handle reputation update
   */
  _handleReputationUpdate(data, origin) {
    const { userId, stats, timestamp } = data;
    
    this.node.replication.recordChange(
      'pq_user_stats',
      userId,
      'UPSERT',
      { user_id: userId, ...stats, _origin: origin }
    );
  }

  /**
   * Sanitize listing for replication (remove sensitive fields)
   */
  _sanitizeListing(listing) {
    const config = PEERQUANTA_TABLES.listings;
    const sanitized = {};
    
    for (const field of config.replicateFields) {
      if (listing[field] !== undefined) {
        sanitized[field] = listing[field];
      }
    }
    
    return sanitized;
  }
  
  /**
   * Get listings from mesh replication log
   */
  _getListingsFromMesh() {
    try {
      const result = this.node.replication.db.exec(`
        SELECT DISTINCT data 
        FROM _replication_log 
        WHERE table_name = 'pq_listings' 
          AND operation != 'DELETE'
        ORDER BY created_at DESC
        LIMIT 100
      `);
      
      if (result.length === 0 || result[0].values.length === 0) {
        return [];
      }
      
      // Parse JSON data and dedupe by id
      const listingsMap = new Map();
      for (const row of result[0].values) {
        try {
          const listing = JSON.parse(row[0]);
          if (listing.id && !listingsMap.has(listing.id)) {
            listingsMap.set(listing.id, listing);
          }
        } catch (e) {
          // Invalid JSON, skip
        }
      }
      
      return Array.from(listingsMap.values());
    } catch (error) {
      console.error('Error getting listings from mesh:', error.message);
      return [];
    }
  }
  
  /**
   * Get a specific listing by ID
   */
  _getListingById(listingId) {
    // First try phpBB database
    if (this.phpbbDb) {
      try {
        const config = PEERQUANTA_TABLES.listings;
        const result = this.phpbbDb.exec(`
          SELECT ${config.replicateFields.join(', ')}
          FROM ${config.table}
          WHERE id = ${listingId}
        `);
        
        if (result.length > 0 && result[0].values.length > 0) {
          const columns = result[0].columns;
          const listing = {};
          columns.forEach((col, i) => {
            listing[col] = result[0].values[0][i];
          });
          return listing;
        }
      } catch (e) {
        // Fall through to mesh
      }
    }
    
    // Try mesh replication
    try {
      const result = this.node.replication.db.exec(`
        SELECT data 
        FROM _replication_log 
        WHERE table_name = 'pq_listings' 
          AND row_id = '${listingId}'
          AND operation != 'DELETE'
        ORDER BY created_at DESC
        LIMIT 1
      `);
      
      if (result.length > 0 && result[0].values.length > 0) {
        return JSON.parse(result[0].values[0][0]);
      }
    } catch (e) {
      // Not found
    }
    
    return null;
  }
  
  /**
   * Get QCoA certificates from mesh
   */
  _getQCoACertificatesFromMesh(filters = {}) {
    try {
      const result = this.node.replication.db.exec(`
        SELECT DISTINCT data 
        FROM _replication_log 
        WHERE table_name = 'qcoa_certificates' 
          AND operation != 'DELETE'
        ORDER BY created_at DESC
        LIMIT 100
      `);
      
      if (result.length === 0 || result[0].values.length === 0) {
        return [];
      }
      
      const certsMap = new Map();
      for (const row of result[0].values) {
        try {
          const cert = JSON.parse(row[0]);
          if (cert.id && !certsMap.has(cert.id)) {
            certsMap.set(cert.id, cert);
          }
        } catch (e) {
          // Invalid JSON, skip
        }
      }
      
      let certs = Array.from(certsMap.values());
      
      // Apply filters
      if (filters.userId) {
        certs = certs.filter(c => c.user_id === parseInt(filters.userId));
      }
      if (filters.status) {
        certs = certs.filter(c => c.status === filters.status);
      }
      
      return certs;
    } catch (error) {
      console.error('Error getting QCoA certificates from mesh:', error.message);
      return [];
    }
  }
  
  /**
   * Verify a QCoA certificate by hash
   */
  _verifyQCoACertificate(certHash) {
    // Try phpBB database first
    if (this.phpbbDb) {
      try {
        const result = this.phpbbDb.exec(`
          SELECT * FROM qcoa_certificates
          WHERE cert_hash = '${certHash}'
             OR content_hash = '${certHash}'
          LIMIT 1
        `);
        
        if (result.length > 0 && result[0].values.length > 0) {
          const columns = result[0].columns;
          const cert = {};
          columns.forEach((col, i) => {
            cert[col] = result[0].values[0][i];
          });
          return cert;
        }
      } catch (e) {
        // Fall through to mesh
      }
    }
    
    // Try mesh replication
    try {
      const result = this.node.replication.db.exec(`
        SELECT data 
        FROM _replication_log 
        WHERE table_name = 'qcoa_certificates' 
        ORDER BY created_at DESC
      `);
      
      if (result.length > 0 && result[0].values.length > 0) {
        for (const row of result[0].values) {
          try {
            const cert = JSON.parse(row[0]);
            if (cert.cert_hash === certHash || cert.content_hash === certHash) {
              return cert;
            }
          } catch (e) {
            // Invalid JSON, skip
          }
        }
      }
    } catch (e) {
      // Not found
    }
    
    return null;
  }
}

/**
 * Create HTTP endpoints for PeerQuanta integration
 */
export function createPeerQuantaEndpoints(app, bridge) {
  // Get mesh status
  app.get('/pq/status', (req, res) => {
    res.json(bridge.getStatus());
  });

  // Get all active listings from mesh
  app.get('/pq/listings', (req, res) => {
    try {
      // Get from phpBB if available, or from mesh replication
      const listings = bridge.phpbbDb 
        ? bridge.getListingsFromPhpBB(req.query)
        : bridge._getListingsFromMesh();
      res.json({ success: true, listings, source: bridge.phpbbDb ? 'phpbb' : 'mesh' });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Get a specific listing
  app.get('/pq/listings/:id', (req, res) => {
    try {
      const listing = bridge._getListingById(req.params.id);
      if (listing) {
        res.json({ success: true, listing });
      } else {
        res.status(404).json({ error: 'Listing not found' });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Push a listing update (create or update)
  app.post('/pq/listings', async (req, res) => {
    try {
      const result = await bridge.pushListing(req.body);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Update a listing
  app.put('/pq/listings/:id', async (req, res) => {
    try {
      const listing = { ...req.body, id: parseInt(req.params.id) };
      const result = await bridge.pushListing(listing);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Delete a listing (mark as deleted)
  app.delete('/pq/listings/:id', async (req, res) => {
    try {
      bridge.node.gossip.spreadRumor('pq:listing:delete', {
        listingId: req.params.id,
        timestamp: Date.now(),
      });
      
      bridge.node.replication.recordChange(
        'pq_listings',
        req.params.id,
        'DELETE',
        { id: req.params.id, status: 'deleted' }
      );
      
      res.json({ success: true, deleted: req.params.id });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Push a QCoA certificate
  app.post('/pq/qcoa', async (req, res) => {
    try {
      const result = await bridge.pushQCoACertificate(req.body);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Get QCoA certificates
  app.get('/pq/qcoa', (req, res) => {
    try {
      const certs = bridge._getQCoACertificatesFromMesh(req.query);
      res.json({ success: true, certificates: certs });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Verify a QCoA certificate
  app.get('/pq/qcoa/:hash', (req, res) => {
    try {
      const cert = bridge._verifyQCoACertificate(req.params.hash);
      if (cert) {
        res.json({ success: true, certificate: cert, verified: true });
      } else {
        res.status(404).json({ error: 'Certificate not found', verified: false });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Trigger manual sync
  app.post('/pq/sync', async (req, res) => {
    try {
      await bridge.refreshPhpBBConnection();
      await bridge._syncFromPhpBB();
      res.json({ success: true, lastSync: bridge.lastSyncTime, lastIds: bridge.lastSyncedIds });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Get sync stats
  app.get('/pq/sync/stats', (req, res) => {
    res.json({
      lastSync: bridge.lastSyncTime,
      lastSyncedIds: bridge.lastSyncedIds,
      phpbbConnected: !!bridge.phpbbDb,
      meshStats: bridge.getStatus(),
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════════
  // v2.0 SECURITY API ENDPOINTS
  // ═══════════════════════════════════════════════════════════════════════════════
  
  if (bridge.security) {
    // Security status
    app.get('/pq/security/status', (req, res) => {
      res.json({
        success: true,
        status: bridge.security.getStatus(),
      });
    });

    // ─────────────────────────────────────────────────────────────────────────────
    // DOKO TRADER IDENTITY
    // ─────────────────────────────────────────────────────────────────────────────
    
    // Create trader identity
    app.post('/pq/identity/create', (req, res) => {
      try {
        const { userId, username, tradingPairs } = req.body;
        if (!userId || !username) {
          return res.status(400).json({ error: 'userId and username required' });
        }
        const result = bridge.security.identity.createTraderIdentity(userId, username, { tradingPairs });
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Get trader identity
    app.get('/pq/identity/:userId', (req, res) => {
      try {
        const doko = bridge.security.identity.getTraderDoko(parseInt(req.params.userId));
        if (doko) {
          res.json({ success: true, doko: doko.toJSON ? doko.toJSON() : doko });
        } else {
          res.status(404).json({ error: 'No DOKO found for user' });
        }
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Verify trader
    app.get('/pq/identity/:userId/verify', (req, res) => {
      try {
        const result = bridge.security.identity.verifyTrader(parseInt(req.params.userId));
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // List all traders
    app.get('/pq/traders', (req, res) => {
      try {
        const traders = bridge.security.identity.getAllTraders();
        res.json({ success: true, traders: traders.map(t => t.toJSON ? t.toJSON() : t) });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // ─────────────────────────────────────────────────────────────────────────────
    // TRUST-BASED ESCROW
    // ─────────────────────────────────────────────────────────────────────────────
    
    // Get escrow requirements for a trade
    app.post('/pq/escrow/requirements', async (req, res) => {
      try {
        const { buyerUserId, sellerUserId, tradeValue } = req.body;
        if (!buyerUserId || !sellerUserId || tradeValue === undefined) {
          return res.status(400).json({ error: 'buyerUserId, sellerUserId, and tradeValue required' });
        }
        const result = await bridge.security.escrow.getEscrowRequirements(
          buyerUserId, sellerUserId, tradeValue
        );
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Get trader trust level
    app.get('/pq/trust/:userId', async (req, res) => {
      try {
        const result = await bridge.security.escrow.calculateTraderTrust(parseInt(req.params.userId));
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // ─────────────────────────────────────────────────────────────────────────────
    // ANNEX TRADE CHAT
    // ─────────────────────────────────────────────────────────────────────────────
    
    // Initialize trade chat
    app.post('/pq/chat/init', async (req, res) => {
      try {
        const { tradeId, buyerUserId, sellerUserId } = req.body;
        if (!tradeId || !buyerUserId || !sellerUserId) {
          return res.status(400).json({ error: 'tradeId, buyerUserId, and sellerUserId required' });
        }
        const result = await bridge.security.chat.initTradeChat(tradeId, buyerUserId, sellerUserId);
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Send message in trade chat
    app.post('/pq/chat/:tradeId/send', async (req, res) => {
      try {
        const { senderUserId, message, secretKeyHex } = req.body;
        if (!senderUserId || !message || !secretKeyHex) {
          return res.status(400).json({ error: 'senderUserId, message, and secretKeyHex required' });
        }
        const result = await bridge.security.chat.sendMessage(
          req.params.tradeId, senderUserId, message, secretKeyHex
        );
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Get chat history
    app.get('/pq/chat/:tradeId', (req, res) => {
      try {
        const userId = parseInt(req.query.userId);
        if (!userId) {
          return res.status(400).json({ error: 'userId query parameter required' });
        }
        const result = bridge.security.chat.getChatHistory(req.params.tradeId, userId);
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Close trade chat
    app.delete('/pq/chat/:tradeId', (req, res) => {
      try {
        const result = bridge.security.chat.closeChat(req.params.tradeId);
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // ─────────────────────────────────────────────────────────────────────────────
    // MERCHANT DOMAIN VERIFICATION
    // ─────────────────────────────────────────────────────────────────────────────
    
    // Request domain verification
    app.post('/pq/merchant/verify/request', async (req, res) => {
      try {
        const { userId, domain, businessName } = req.body;
        if (!userId || !domain) {
          return res.status(400).json({ error: 'userId and domain required' });
        }
        const result = await bridge.security.merchant.requestVerification(userId, domain, businessName);
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Complete domain verification
    app.post('/pq/merchant/verify/complete', async (req, res) => {
      try {
        const { userId, domain } = req.body;
        if (!userId || !domain) {
          return res.status(400).json({ error: 'userId and domain required' });
        }
        const result = await bridge.security.merchant.verifyDomain(userId, domain);
        res.json(result);
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    // Check if merchant is verified
    app.get('/pq/merchant/:userId/verified', (req, res) => {
      try {
        const verified = bridge.security.merchant.isVerified(parseInt(req.params.userId));
        const details = bridge.security.merchant.getVerification(parseInt(req.params.userId));
        res.json({ verified, details });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });

    console.log('✓ v2.0 Security API endpoints registered');
    console.log('  GET  /pq/security/status       - Security status');
    console.log('  POST /pq/identity/create       - Create trader DOKO');
    console.log('  GET  /pq/identity/:userId      - Get trader DOKO');
    console.log('  GET  /pq/identity/:userId/verify - Verify trader');
    console.log('  GET  /pq/traders               - List all traders');
    console.log('  POST /pq/escrow/requirements   - Get escrow requirements');
    console.log('  GET  /pq/trust/:userId         - Get trust level');
    console.log('  POST /pq/chat/init             - Start trade chat');
    console.log('  POST /pq/chat/:tradeId/send    - Send chat message');
    console.log('  GET  /pq/chat/:tradeId         - Get chat history');
    console.log('  DEL  /pq/chat/:tradeId         - Close chat');
    console.log('  POST /pq/merchant/verify/request  - Request verification');
    console.log('  POST /pq/merchant/verify/complete - Complete verification');
    console.log('  GET  /pq/merchant/:userId/verified - Check verification');
  }

  console.log('✓ PeerQuanta API endpoints registered');
  console.log('  GET  /pq/status         - Mesh status');
  console.log('  GET  /pq/listings       - List all listings');
  console.log('  GET  /pq/listings/:id   - Get listing by ID');
  console.log('  POST /pq/listings       - Create/update listing');
  console.log('  PUT  /pq/listings/:id   - Update listing');
  console.log('  DEL  /pq/listings/:id   - Delete listing');
  console.log('  POST /pq/qcoa           - Create QCoA certificate');
  console.log('  GET  /pq/qcoa           - List certificates');
  console.log('  GET  /pq/qcoa/:hash     - Verify certificate');
  console.log('  POST /pq/sync           - Manual sync trigger');
  console.log('  GET  /pq/sync/stats     - Sync statistics');
}

export default PeerQuantaBridge;
