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
      identity: { nodeId, publicKey: 'mock-pubkey-' + nodeId },
      sign(message) { return 'mock-sig-' + nodeId; },
      verify(message, signature, publicKey) { return signature.startsWith('mock-sig-'); },
    },
    peers: new Map(),
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
    // Register the remote peer's public key so sig verification can find it
    mesh.peers.set('remote-node-abc', {
      identity: { publicKey: 'mock-pubkey-remote-node-abc' },
    });

    const changeData = JSON.stringify({ title: 'Remote listing' });
    const vectorClock = 'remote-node-abc-1234-xyz';
    // Build signing payload matching what recordChange produces
    const sigPayload = JSON.stringify({
      tableName: 'pq_listings', rowId: 'remote-row-1', operation: 'INSERT',
      data: changeData, nodeId: 'remote-node-abc', vectorClock,
    });

    const result = engine.applyChange({
      table_name: 'pq_listings',
      row_id: 'remote-row-1',
      operation: 'INSERT',
      data: changeData,
      node_id: 'remote-node-abc',
      vector_clock: vectorClock,
      created_at: Date.now(),
      signature: 'mock-sig-remote-node-abc',
    });
    assert.strictEqual(result, true);
  });

  it('rejects duplicate change (same vector_clock)', () => {
    // Ensure peer key exists
    mesh.peers.set('remote-node-abc', {
      identity: { publicKey: 'mock-pubkey-remote-node-abc' },
    });

    const changeData = JSON.stringify({ title: 'Dedup' });
    const vectorClock = 'dedup-clock-12345';

    const change = {
      table_name: 'pq_listings',
      row_id: 'dedup-row',
      operation: 'INSERT',
      data: changeData,
      node_id: 'remote-node-abc',
      vector_clock: vectorClock,
      created_at: Date.now(),
      signature: 'mock-sig-remote-node-abc',
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

// =============================================================================
// HIGH 11.2 — Replication signature enforcement
// =============================================================================

describe('ReplicationEngine: Signature Enforcement', () => {
  let engine;
  let mesh;
  const dbPath = TEST_DB_PATH + '.sigtest';

  before(async () => {
    mesh = createMockMesh();
    engine = new ReplicationEngine(mesh, dbPath);
    await engine.init();
  });

  after(() => {
    engine.stopSync();
    if (existsSync(dbPath)) rmSync(dbPath);
  });

  it('recordChange produces a signed entry in the replication log', () => {
    engine.recordChange('pq_listings', 'sig-row-1', 'INSERT', { title: 'Signed' });
    const changes = engine.getChangesSince(0);
    const lastChange = changes[changes.length - 1];
    assert.ok(lastChange.signature, 'Replication change should have a signature');
    assert.ok(lastChange.signature.startsWith('mock-sig-'), 'Signature should come from identity.sign()');
  });

  it('applyChange rejects unsigned changes', () => {
    const result = engine.applyChange({
      table_name: 'pq_listings',
      row_id: 'unsigned-row',
      operation: 'INSERT',
      data: JSON.stringify({ title: 'No sig' }),
      node_id: 'remote-node-xyz',
      vector_clock: 'unsigned-vc-1',
      created_at: Date.now(),
      // no signature
    });
    assert.strictEqual(result, false, 'Unsigned change should be rejected');
  });

  it('applyChange rejects changes from unknown nodes', () => {
    const result = engine.applyChange({
      table_name: 'pq_listings',
      row_id: 'unknown-node-row',
      operation: 'INSERT',
      data: JSON.stringify({ title: 'Unknown' }),
      node_id: 'totally-unknown-node',
      vector_clock: 'unknown-vc-1',
      created_at: Date.now(),
      signature: 'mock-sig-totally-unknown-node',
    });
    assert.strictEqual(result, false, 'Change from unknown node should be rejected');
  });

  it('applyChange rejects changes with invalid signatures', () => {
    // Register peer first
    mesh.peers.set('bad-sig-peer', { identity: { publicKey: 'mock-pubkey-bad-sig-peer' } });

    // Override verify to reject 'forged-sig'
    const origVerify = mesh.identity.verify;
    mesh.identity.verify = (msg, sig, pk) => sig !== 'forged-sig';

    const result = engine.applyChange({
      table_name: 'pq_listings',
      row_id: 'bad-sig-row',
      operation: 'INSERT',
      data: JSON.stringify({ title: 'Bad sig' }),
      node_id: 'bad-sig-peer',
      vector_clock: 'bad-sig-vc-1',
      created_at: Date.now(),
      signature: 'forged-sig',
    });

    mesh.identity.verify = origVerify;
    assert.strictEqual(result, false, 'Change with invalid signature should be rejected');
  });

  it('applyChange accepts validly signed changes from known peers', () => {
    mesh.peers.set('valid-peer', { identity: { publicKey: 'mock-pubkey-valid-peer' } });

    const result = engine.applyChange({
      table_name: 'pq_listings',
      row_id: 'valid-sig-row',
      operation: 'INSERT',
      data: JSON.stringify({ title: 'Valid' }),
      node_id: 'valid-peer',
      vector_clock: 'valid-vc-1',
      created_at: Date.now(),
      signature: 'mock-sig-valid-peer',
    });
    assert.strictEqual(result, true, 'Validly signed change should be accepted');
  });
});
