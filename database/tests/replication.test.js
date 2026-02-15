/**
 * Database Replication Engine Tests
 * 
 * @module database/tests/replication.test
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import { existsSync, rmSync, mkdirSync } from 'fs';
import { join } from 'path';

import { ReplicationEngine } from '../replication.js';

const TEST_DB_PATH = join(import.meta.dirname, '..', '..', 'data', '_test_repl_' + Date.now() + '.db');

console.log('\n💾 Database Replication Engine Tests\n');
console.log('='.repeat(60));

// =============================================================================
// Mock mesh
// =============================================================================

function createMockMesh(nodeId = 'repl-node-' + Math.random().toString(36).slice(2, 10)) {
  const handlers = {};
  return {
    identity: {
      identity: { nodeId },
    },
    on(event, handler) { handlers[event] = handler; },
    off(event) { delete handlers[event]; },
    emit(event, ...args) { handlers[event]?.(...args); },
    broadcast(msg) {},
    sendTo(nodeId, msg) {},
    getPeers() { return []; },
    _handlers: handlers,
  };
}

// =============================================================================
// Initialization
// =============================================================================

describe('ReplicationEngine: Init', () => {
  let engine;
  let mesh;

  before(async () => {
    mesh = createMockMesh();
    engine = new ReplicationEngine(mesh, TEST_DB_PATH);
    await engine.init();
  });

  after(() => {
    engine.stopSync();
    if (existsSync(TEST_DB_PATH)) rmSync(TEST_DB_PATH);
  });

  it('creates the database file', () => {
    assert.ok(existsSync(TEST_DB_PATH), 'DB file should exist after init');
  });

  it('creates _replication_log table', () => {
    const result = engine.db.exec("SELECT name FROM sqlite_master WHERE type='table' AND name='_replication_log'");
    assert.strictEqual(result.length, 1);
  });

  it('creates _replication_state table', () => {
    const result = engine.db.exec("SELECT name FROM sqlite_master WHERE type='table' AND name='_replication_state'");
    assert.strictEqual(result.length, 1);
  });

  it('sets nodeId from mesh identity', () => {
    assert.strictEqual(engine.nodeId, mesh.identity.identity.nodeId);
  });
});

// =============================================================================
// recordChange + getChangesSince
// =============================================================================

describe('ReplicationEngine: Changes', () => {
  let engine;
  let mesh;
  const dbPath = TEST_DB_PATH + '.changes';

  before(async () => {
    mesh = createMockMesh();
    engine = new ReplicationEngine(mesh, dbPath);
    await engine.init();
  });

  after(() => {
    engine.stopSync();
    if (existsSync(dbPath)) rmSync(dbPath);
  });

  it('recordChange inserts into log for replicated table', () => {
    engine.recordChange('pq_listings', 'row1', 'INSERT', { title: 'Test' });
    
    const changes = engine.getChangesSince(0);
    assert.ok(changes.length >= 1, 'Should have at least one change');
    assert.strictEqual(changes[0].table_name, 'pq_listings');
    assert.strictEqual(changes[0].row_id, 'row1');
    assert.strictEqual(changes[0].operation, 'INSERT');
  });

  it('recordChange ignores non-replicated tables', () => {
    const beforeCount = engine.getChangesSince(0).length;
    engine.recordChange('non_replicated_table', 'row1', 'INSERT', { data: 1 });
    const afterCount = engine.getChangesSince(0).length;
    assert.strictEqual(afterCount, beforeCount, 'Non-replicated table changes should be ignored');
  });

  it('getChangesSince filters by timestamp', () => {
    const now = Date.now();
    engine.recordChange('pq_chat_messages', 'msg1', 'INSERT', { text: 'hi' });
    
    // Future timestamp should return nothing (no changes after future)
    const futureChanges = engine.getChangesSince(now + 100000);
    assert.strictEqual(futureChanges.length, 0);
  });
});

// =============================================================================
// applyChange
// =============================================================================

describe('ReplicationEngine: applyChange', () => {
  let engine;
  let mesh;
  const dbPath = TEST_DB_PATH + '.apply';

  before(async () => {
    mesh = createMockMesh();
    engine = new ReplicationEngine(mesh, dbPath);
    await engine.init();
  });

  after(() => {
    engine.stopSync();
    if (existsSync(dbPath)) rmSync(dbPath);
  });

  it('applies a new change and returns true', () => {
    const result = engine.applyChange({
      table_name: 'pq_listings',
      row_id: 'remote-row-1',
      operation: 'INSERT',
      data: JSON.stringify({ title: 'Remote listing' }),
      node_id: 'remote-node-abc',
      vector_clock: 'remote-node-abc-1234-xyz',
      created_at: Date.now(),
    });
    assert.strictEqual(result, true);
  });

  it('rejects duplicate change (same vector_clock)', () => {
    const change = {
      table_name: 'pq_listings',
      row_id: 'dedup-row',
      operation: 'INSERT',
      data: JSON.stringify({ title: 'Dedup' }),
      node_id: 'remote-node-abc',
      vector_clock: 'dedup-clock-12345',
      created_at: Date.now(),
    };
    engine.applyChange(change);
    const second = engine.applyChange(change);
    assert.strictEqual(second, false, 'Duplicate should return false');
  });
});

// =============================================================================
// getStats
// =============================================================================

describe('ReplicationEngine: Stats', () => {
  let engine;
  let mesh;
  const dbPath = TEST_DB_PATH + '.stats';

  before(async () => {
    mesh = createMockMesh();
    engine = new ReplicationEngine(mesh, dbPath);
    await engine.init();
    engine.recordChange('pq_listings', 'r1', 'INSERT', { x: 1 });
  });

  after(() => {
    engine.stopSync();
    if (existsSync(dbPath)) rmSync(dbPath);
  });

  it('returns replication log size', () => {
    const stats = engine.getStats();
    assert.ok(stats.replicationLogSize >= 1);
  });

  it('returns replicated tables list', () => {
    const stats = engine.getStats();
    assert.ok(Array.isArray(stats.replicatedTables));
    assert.ok(stats.replicatedTables.includes('pq_listings'));
  });
});

// =============================================================================
// Sync lifecycle
// =============================================================================

describe('ReplicationEngine: Sync', () => {
  it('startSync and stopSync manage interval', async () => {
    const mesh = createMockMesh();
    const dbPath = TEST_DB_PATH + '.sync';
    const engine = new ReplicationEngine(mesh, dbPath);
    await engine.init();
    
    engine.startSync(60000); // Long interval so it doesn't fire
    assert.ok(engine.syncInterval !== null, 'syncInterval should be set');
    
    engine.stopSync();
    assert.strictEqual(engine.syncInterval, null, 'syncInterval should be null after stop');
    
    if (existsSync(dbPath)) rmSync(dbPath);
  });
});
