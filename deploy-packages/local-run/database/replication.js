/**
 * Lantern Replication Engine
 * SQLite sync with timestamp-based conflict resolution
 * Uses sql.js (pure JS/WASM) for cross-platform compatibility
 */

import initSqlJs from 'sql.js';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { dirname } from 'path';
import { MessageTypes } from '../mesh/network.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('database:replication');

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
 * Tables to replicate across the mesh
 */
const REPLICATED_TABLES = [
  'pq_listings',
  'pq_chat_messages',
  'qcoa_certificates',
];

/**
 * Replication Engine
 * Handles SQLite synchronization between nodes
 */
export class ReplicationEngine {
  constructor(mesh, dbPath = './data/peerquanta.db') {
    this.mesh = mesh;
    this.dbPath = dbPath;
    this.db = null;
    this.nodeId = mesh.identity.identity.nodeId;
    this.identity = mesh.identity;  // For ML-DSA-65 signing/verification
    this.syncInterval = null;
  }

  /**
   * Initialize the database
   */
  async init() {
    // Ensure directory exists
    const dir = dirname(this.dbPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    // Initialize sql.js
    const SqlJs = await initSQL();

    // Load existing database or create new one
    if (existsSync(this.dbPath)) {
      const buffer = readFileSync(this.dbPath);
      this.db = new SqlJs.Database(buffer);
    } else {
      this.db = new SqlJs.Database();
    }

    // Create replication metadata table
    this.db.run(`
      CREATE TABLE IF NOT EXISTS _replication_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        table_name TEXT NOT NULL,
        row_id TEXT NOT NULL,
        operation TEXT NOT NULL,
        data TEXT,
        node_id TEXT NOT NULL,
        vector_clock TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        synced_to TEXT DEFAULT '[]'
      )
    `);
    
    this.db.run(`
      CREATE TABLE IF NOT EXISTS _replication_state (
        peer_node_id TEXT PRIMARY KEY,
        last_sync_at INTEGER,
        last_vector_clock TEXT
      )
    `);

    // Create index if not exists
    try {
      this.db.run(`CREATE INDEX idx_repl_log_sync ON _replication_log(table_name, created_at)`);
    } catch (e) {
      // Index already exists
    }

    // Add signature column for ML-DSA-65 authenticated replication
    try {
      this.db.run(`ALTER TABLE _replication_log ADD COLUMN signature TEXT`);
    } catch (e) {
      // Column already exists
    }

    this._saveDb();
    log.info('Database initialized', { path: this.dbPath });

    // Setup mesh handlers
    this._setupMeshHandlers();

    return this;
  }

  /**
   * Save database to disk
   */
  _saveDb() {
    const data = this.db.export();
    const buffer = Buffer.from(data);
    writeFileSync(this.dbPath, buffer);
  }

  /**
   * Start automatic sync
   */
  startSync(intervalMs = 5000) {
    this.syncInterval = setInterval(() => {
      this.syncWithPeers();
    }, intervalMs);
    log.info('Auto-sync started', { intervalSeconds: intervalMs / 1000 });
  }

  /**
   * Stop automatic sync
   */
  stopSync() {
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
  }

  /**
   * Record a local change for replication
   */
  recordChange(tableName, rowId, operation, data) {
    if (!REPLICATED_TABLES.includes(tableName)) return;

    const vectorClock = this._generateVectorClock();
    const dataJson = JSON.stringify(data);

    // Sign the change payload (ML-DSA-65) for authenticated replication
    const sigPayload = JSON.stringify({
      tableName, rowId: String(rowId), operation, data: dataJson,
      nodeId: this.nodeId, vectorClock,
    });
    const signature = this.identity.sign(sigPayload);
    
    this.db.run(
      `INSERT INTO _replication_log 
       (table_name, row_id, operation, data, node_id, vector_clock, created_at, signature)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [tableName, String(rowId), operation, dataJson, this.nodeId, vectorClock, Date.now(), signature]
    );
    
    this._saveDb();
  }

  /**
   * Sync with all connected peers
   */
  async syncWithPeers() {
    const peers = this.mesh.getPeers();
    
    for (const peer of peers) {
      await this.syncWithPeer(peer.nodeId);
    }
  }

  /**
   * Sync with a specific peer
   */
  async syncWithPeer(peerNodeId) {
    // Get last sync state for this peer (parameterized to prevent SQL injection)
    let lastSyncAt = 0;
    try {
      const stmt = this.db.prepare(
        'SELECT last_sync_at FROM _replication_state WHERE peer_node_id = ?'
      );
      stmt.bind([peerNodeId]);
      if (stmt.step()) {
        lastSyncAt = stmt.get()[0] || 0;
      }
      stmt.free();
    } catch (e) {
      log.warn('Failed to query sync state', { peer: peerNodeId.slice(0, 12), error: e.message });
    }

    // Request changes from peer since last sync
    try {
      this.mesh.sendTo(peerNodeId, {
        type: MessageTypes.SYNC_REQUEST,
        since: lastSyncAt,
        tables: REPLICATED_TABLES,
      });
    } catch (e) {
      // Peer might have disconnected
    }
  }

  /**
   * Apply a replicated change from another node
   */
  applyChange(change) {
    const { table_name, row_id, operation, data, node_id, vector_clock, created_at, signature } = change;

    // Verify ML-DSA-65 signature before trusting remote change
    if (!signature) {
      log.warn('Rejecting unsigned replication change', { nodeId: node_id?.slice(0, 12), table: table_name });
      return false;
    }
    const peerPubKey = this._getPeerPublicKey(node_id);
    if (!peerPubKey) {
      log.warn('Rejecting replication change from unknown node (no public key)', { nodeId: node_id?.slice(0, 12) });
      return false;
    }
    const sigPayload = JSON.stringify({
      tableName: table_name, rowId: row_id, operation, data,
      nodeId: node_id, vectorClock: vector_clock,
    });
    if (!this.identity.verify(sigPayload, signature, peerPubKey)) {
      log.warn('Rejecting replication change with invalid signature', { nodeId: node_id?.slice(0, 12), table: table_name });
      return false;
    }

    // Check if we already have this change (parameterized)
    let alreadyExists = false;
    try {
      const stmt = this.db.prepare(
        'SELECT id FROM _replication_log WHERE table_name = ? AND row_id = ? AND vector_clock = ?'
      );
      stmt.bind([table_name, row_id, vector_clock]);
      alreadyExists = stmt.step();
      stmt.free();
    } catch (e) {
      log.warn('Failed to check existing change', { error: e.message });
    }

    if (alreadyExists) {
      return false; // Already applied
    }

    // Record the change
    this.db.run(
      `INSERT INTO _replication_log 
       (table_name, row_id, operation, data, node_id, vector_clock, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [table_name, row_id, operation, data, node_id, vector_clock, created_at]
    );

    this._saveDb();
    log.debug('Applied change', { operation, table: table_name, rowId: row_id, nodeId: node_id.slice(0, 12) });
    return true;
  }

  /**
   * Get changes since a timestamp
   */
  getChangesSince(since, tables = REPLICATED_TABLES) {
    const placeholders = tables.map(() => '?').join(',');
    
    try {
      const stmt = this.db.prepare(
        `SELECT * FROM _replication_log 
         WHERE created_at > ? AND table_name IN (${placeholders})
         ORDER BY created_at ASC
         LIMIT 1000`
      );
      stmt.bind([since, ...tables]);
      
      const columns = stmt.getColumnNames();
      const results = [];
      while (stmt.step()) {
        const row = stmt.get();
        const obj = {};
        columns.forEach((col, i) => { obj[col] = row[i]; });
        results.push(obj);
      }
      stmt.free();
      return results;
    } catch (e) {
      log.warn('Failed to get changes', { error: e.message });
      return [];
    }
  }

  /**
   * Get database stats
   */
  getStats() {
    const logResult = this.db.exec('SELECT COUNT(*) as count FROM _replication_log');
    const logCount = logResult.length > 0 ? logResult[0].values[0][0] : 0;
    
    const statesResult = this.db.exec('SELECT * FROM _replication_state');
    const peerStates = statesResult.length > 0 ? statesResult[0].values : [];
    
    return {
      replicationLogSize: logCount,
      peerStates,
      replicatedTables: REPLICATED_TABLES,
    };
  }

  // ===== Private Methods =====

  /**
   * Resolve a peer's public key from mesh state.
   * Checks WS peers, relay keys, SHERPA registry, and self.
   */
  _getPeerPublicKey(nodeId) {
    // Self
    if (nodeId === this.nodeId) {
      return this.identity.identity.publicKey;
    }
    // WS peer info
    if (this.mesh?.peers) {
      const peer = this.mesh.peers.get(nodeId);
      if (peer?.identity?.publicKey) return peer.identity.publicKey;
    }
    // Relay peer keys (stored during signed registration)
    if (this.mesh?._relayPeerKeys) {
      const key = this.mesh._relayPeerKeys.get(nodeId);
      if (key) return key;
    }
    // SHERPA registry
    if (this.mesh?.sherpa?.registry) {
      const regPeer = this.mesh.sherpa.registry.get(nodeId);
      if (regPeer?.publicKey) return regPeer.publicKey;
    }
    return null;
  }

  _generateVectorClock() {
    const timestamp = Date.now();
    const random = Math.random().toString(36).slice(2, 8);
    return `${this.nodeId.slice(0, 12)}-${timestamp}-${random}`;
  }

  _setupMeshHandlers() {
    // Handle sync requests
    this.mesh.on(MessageTypes.SYNC_REQUEST, (msg, ws, peerNodeId) => {
      if (!peerNodeId) return;
      
      log.debug('Sync request received', { from: peerNodeId.slice(0, 12), since: msg.since });
      
      const changes = this.getChangesSince(msg.since, msg.tables);
      
      this.mesh.sendTo(peerNodeId, {
        type: MessageTypes.SYNC_RESPONSE,
        changes,
        asOf: Date.now(),
      });
    });

    // Handle sync responses
    this.mesh.on(MessageTypes.SYNC_RESPONSE, (msg, ws, peerNodeId) => {
      if (!peerNodeId) return;
      
      log.debug('Sync response received', { from: peerNodeId.slice(0, 12), changes: msg.changes.length });
      
      let applied = 0;
      for (const change of msg.changes) {
        if (this.applyChange(change)) {
          applied++;
        }
      }
      
      // Update sync state
      this.db.run(
        `INSERT OR REPLACE INTO _replication_state (peer_node_id, last_sync_at) VALUES (?, ?)`,
        [peerNodeId, msg.asOf]
      );
      this._saveDb();
      
      if (applied > 0) {
        log.info('Applied new changes', { count: applied, from: peerNodeId.slice(0, 12) });
      }
    });

    // Handle direct replication pushes
    this.mesh.on(MessageTypes.REPLICATE, (msg, ws, peerNodeId) => {
      this.applyChange(msg.change);
    });
  }
}

export default ReplicationEngine;
