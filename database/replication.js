/**
 * Lantern Replication Engine
 * SQLite sync with timestamp-based conflict resolution
 * Uses sql.js (pure JS/WASM) for cross-platform compatibility
 */

import initSqlJs from 'sql.js';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { dirname } from 'path';
import { MessageTypes } from '../mesh/network.js';

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

    this._saveDb();
    console.log(`✓ Database initialized: ${this.dbPath}`);

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
    console.log(`✓ Auto-sync started (every ${intervalMs / 1000}s)`);
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
    
    this.db.run(
      `INSERT INTO _replication_log 
       (table_name, row_id, operation, data, node_id, vector_clock, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [tableName, String(rowId), operation, JSON.stringify(data), this.nodeId, vectorClock, Date.now()]
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
    // Get last sync state for this peer
    const result = this.db.exec(
      `SELECT last_sync_at FROM _replication_state WHERE peer_node_id = '${peerNodeId}'`
    );
    
    const lastSyncAt = result.length > 0 && result[0].values.length > 0 
      ? result[0].values[0][0] 
      : 0;

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
    const { table_name, row_id, operation, data, node_id, vector_clock, created_at } = change;

    // Check if we already have this change
    const existing = this.db.exec(
      `SELECT id FROM _replication_log 
       WHERE table_name = '${table_name}' AND row_id = '${row_id}' AND vector_clock = '${vector_clock}'`
    );

    if (existing.length > 0 && existing[0].values.length > 0) {
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
    console.log(`  ↓ Applied: ${operation} ${table_name}:${row_id} from ${node_id.slice(0, 12)}...`);
    return true;
  }

  /**
   * Get changes since a timestamp
   */
  getChangesSince(since, tables = REPLICATED_TABLES) {
    const tableList = tables.map(t => `'${t}'`).join(',');
    
    const result = this.db.exec(
      `SELECT * FROM _replication_log 
       WHERE created_at > ${since} AND table_name IN (${tableList})
       ORDER BY created_at ASC
       LIMIT 1000`
    );

    if (result.length === 0) return [];

    // Convert to objects
    const columns = result[0].columns;
    return result[0].values.map(row => {
      const obj = {};
      columns.forEach((col, i) => {
        obj[col] = row[i];
      });
      return obj;
    });
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

  _generateVectorClock() {
    const timestamp = Date.now();
    const random = Math.random().toString(36).slice(2, 8);
    return `${this.nodeId.slice(0, 12)}-${timestamp}-${random}`;
  }

  _setupMeshHandlers() {
    // Handle sync requests
    this.mesh.on(MessageTypes.SYNC_REQUEST, (msg, ws, peerNodeId) => {
      if (!peerNodeId) return;
      
      console.log(`  ← Sync request from ${peerNodeId.slice(0, 12)}... (since ${msg.since})`);
      
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
      
      console.log(`  → Sync response from ${peerNodeId.slice(0, 12)}...: ${msg.changes.length} changes`);
      
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
        console.log(`  ✓ Applied ${applied} new changes from ${peerNodeId.slice(0, 12)}...`);
      }
    });

    // Handle direct replication pushes
    this.mesh.on(MessageTypes.REPLICATE, (msg, ws, peerNodeId) => {
      this.applyChange(msg.change);
    });
  }
}

export default ReplicationEngine;
