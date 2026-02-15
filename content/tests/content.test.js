/**
 * Content Module Tests — ContentStore, ContentMetadata, ConsensusProof, computeContentHash
 * 
 * @module content/tests/content.test
 */

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import { existsSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';

import {
  ContentStore,
  ContentType,
  ContentStatus,
  ContentMetadata,
  ConsensusProof,
  computeContentHash,
  deriveContentName,
} from '../store.js';

const TEST_DATA_DIR = join(import.meta.dirname, '..', '..', 'data', '_test_content_' + Date.now());

console.log('\n📦 Content Module Tests\n');
console.log('='.repeat(60));

// =============================================================================
// computeContentHash
// =============================================================================

describe('computeContentHash', () => {
  it('hashes a string', () => {
    const hash = computeContentHash('hello yakmesh');
    assert.strictEqual(typeof hash, 'string');
    assert.strictEqual(hash.length, 64, 'SHA3-256 hex should be 64 chars');
  });

  it('produces deterministic output', () => {
    const a = computeContentHash('deterministic');
    const b = computeContentHash('deterministic');
    assert.strictEqual(a, b);
  });

  it('produces different hashes for different input', () => {
    const a = computeContentHash('alpha');
    const b = computeContentHash('beta');
    assert.notStrictEqual(a, b);
  });

  it('hashes a Buffer', () => {
    const hash = computeContentHash(Buffer.from('buffer content'));
    assert.strictEqual(hash.length, 64);
  });

  it('hashes a Uint8Array', () => {
    const hash = computeContentHash(new Uint8Array([1, 2, 3]));
    assert.strictEqual(hash.length, 64);
  });

  it('hashes an object (JSON-serialized)', () => {
    const hash = computeContentHash({ key: 'value' });
    assert.strictEqual(hash.length, 64);
  });

  it('object hash is deterministic for same shape', () => {
    const a = computeContentHash({ a: 1, b: 2 });
    const b = computeContentHash({ a: 1, b: 2 });
    assert.strictEqual(a, b);
  });
});

// =============================================================================
// deriveContentName
// =============================================================================

describe('deriveContentName', () => {
  it('returns a human-readable string', () => {
    const hash = computeContentHash('test content');
    const name = deriveContentName(hash);
    assert.strictEqual(typeof name, 'string');
    assert.ok(name.length > 0, 'Name should be non-empty');
  });

  it('is deterministic', () => {
    const hash = computeContentHash('stable name');
    const a = deriveContentName(hash);
    const b = deriveContentName(hash);
    assert.strictEqual(a, b);
  });

  it('uses hyphenated words', () => {
    const hash = computeContentHash('with dashes');
    const name = deriveContentName(hash);
    assert.ok(name.includes('-'), `Name "${name}" should contain hyphens`);
  });
});

// =============================================================================
// ContentType constants
// =============================================================================

describe('ContentType', () => {
  it('has expected MIME types', () => {
    assert.strictEqual(ContentType.JSON, 'application/json');
    assert.strictEqual(ContentType.HTML, 'text/html');
    assert.strictEqual(ContentType.TEXT, 'text/plain');
    assert.strictEqual(ContentType.BINARY, 'application/octet-stream');
    assert.strictEqual(ContentType.JAVASCRIPT, 'application/javascript');
    assert.strictEqual(ContentType.CSS, 'text/css');
  });
});

// =============================================================================
// ContentStatus constants
// =============================================================================

describe('ContentStatus', () => {
  it('has all status values', () => {
    assert.strictEqual(ContentStatus.LOCAL, 'local');
    assert.strictEqual(ContentStatus.PENDING, 'pending');
    assert.strictEqual(ContentStatus.VERIFIED, 'verified');
    assert.strictEqual(ContentStatus.REJECTED, 'rejected');
  });
});

// =============================================================================
// ConsensusProof
// =============================================================================

describe('ConsensusProof', () => {
  it('constructs with defaults', () => {
    const proof = new ConsensusProof({ contentHash: 'abc123' });
    assert.strictEqual(proof.contentHash, 'abc123');
    assert.strictEqual(proof.validators.length, 0);
    assert.strictEqual(proof.quorum, 0);
  });

  it('hasQuorum returns false when no validators', () => {
    const proof = new ConsensusProof({ contentHash: 'abc', quorum: 2 });
    assert.strictEqual(proof.hasQuorum(), false);
  });

  it('addValidator adds unique validators', () => {
    const proof = new ConsensusProof({ contentHash: 'abc', quorum: 2 });
    proof.addValidator('node1', 'sig1');
    proof.addValidator('node2', 'sig2');
    assert.strictEqual(proof.validators.length, 2);
  });

  it('addValidator deduplicates by nodeId', () => {
    const proof = new ConsensusProof({ contentHash: 'abc', quorum: 1 });
    proof.addValidator('node1', 'sig1');
    proof.addValidator('node1', 'sig1_again');
    assert.strictEqual(proof.validators.length, 1);
  });

  it('hasQuorum returns true when quorum met', () => {
    const proof = new ConsensusProof({ contentHash: 'abc', quorum: 2 });
    proof.addValidator('node1', 'sig1');
    proof.addValidator('node2', 'sig2');
    assert.strictEqual(proof.hasQuorum(), true);
  });

  it('toJSON round-trips via fromJSON', () => {
    const proof = new ConsensusProof({ contentHash: 'abc', quorum: 2, networkId: 'net1' });
    proof.addValidator('n1', 's1');
    const json = proof.toJSON();
    const restored = ConsensusProof.fromJSON(json);
    assert.strictEqual(restored.contentHash, 'abc');
    assert.strictEqual(restored.quorum, 2);
    assert.strictEqual(restored.validators.length, 1);
  });
});

// =============================================================================
// ContentStore — filesystem-backed content storage
// =============================================================================

describe('ContentStore', () => {
  let store;

  before(async () => {
    store = new ContentStore({ dataDir: TEST_DATA_DIR, quorumSize: 2 });
    await store.init();
  });

  after(() => {
    // Clean up test data
    if (existsSync(TEST_DATA_DIR)) {
      rmSync(TEST_DATA_DIR, { recursive: true, force: true });
    }
  });

  it('creates data directories on init', () => {
    assert.ok(existsSync(join(TEST_DATA_DIR, 'objects')));
    assert.ok(existsSync(join(TEST_DATA_DIR, 'meta')));
  });

  it('stores string content and returns hash + ioName', async () => {
    const result = await store.store('hello yakmesh', { publish: false });
    assert.strictEqual(typeof result.hash, 'string');
    assert.strictEqual(result.hash.length, 64);
    assert.ok(result.ioName, 'Should have an iO name');
    assert.strictEqual(result.status, 'stored');
  });

  it('stores return "exists" for duplicate content', async () => {
    await store.store('duplicate test 123', { publish: false });
    const second = await store.store('duplicate test 123', { publish: false });
    assert.strictEqual(second.status, 'exists');
  });

  it('retrieves stored content via get()', async () => {
    const result = await store.store('retrieve me', { publish: false });
    const content = store.get(result.hash);
    assert.ok(content, 'Content should be retrievable');
  });

  it('has() returns true for existing content', async () => {
    const result = await store.store('existence check', { publish: false });
    assert.strictEqual(store.has(result.hash), true);
  });

  it('has() returns false for missing content', () => {
    assert.strictEqual(store.has('0'.repeat(64)), false);
  });

  it('getMeta() returns metadata', async () => {
    const result = await store.store('meta test', { publish: false, tags: ['test'] });
    const meta = store.getMeta(result.hash);
    assert.ok(meta);
    assert.strictEqual(meta.hash, result.hash);
    assert.deepStrictEqual(meta.tags, ['test']);
  });

  it('getWithProof() returns content + meta', async () => {
    const result = await store.store('proof test', { publish: false });
    const full = store.getWithProof(result.hash);
    assert.ok(full);
    assert.ok(full.content);
    assert.ok(full.meta);
    assert.strictEqual(full.hash, result.hash);
  });

  it('delete() removes content from disk and cache', async () => {
    const result = await store.store('delete me', { publish: false });
    store.delete(result.hash);
    assert.strictEqual(store.has(result.hash), false);
    assert.strictEqual(store.get(result.hash), null);
  });

  it('list() returns stored items', async () => {
    const items = store.list();
    assert.ok(Array.isArray(items));
    assert.ok(items.length > 0, 'Should have items after storing');
  });

  it('list() filters by tag', async () => {
    await store.store('tagged content', { publish: false, tags: ['unique_filter_tag'] });
    const items = store.list({ tag: 'unique_filter_tag' });
    assert.ok(items.length >= 1);
    assert.ok(items.every(i => i.tags.includes('unique_filter_tag')));
  });

  it('list() filters by status', async () => {
    const items = store.list({ status: ContentStatus.LOCAL });
    assert.ok(items.every(i => i.status === ContentStatus.LOCAL));
  });

  it('getStats() returns summary', () => {
    const stats = store.getStats();
    assert.strictEqual(typeof stats.totalObjects, 'number');
    assert.strictEqual(typeof stats.totalSize, 'number');
    assert.ok(stats.totalObjects > 0);
  });

  it('resolves iO name via get()', async () => {
    const result = await store.store('name lookup test', { publish: false });
    const byName = store.get(result.ioName);
    assert.ok(byName, `Should resolve iO name "${result.ioName}" to content`);
  });

  it('enforces maxContentSize', async () => {
    const tinyStore = new ContentStore({ dataDir: TEST_DATA_DIR + '_tiny', maxContentSize: 10 });
    await tinyStore.init();
    await assert.rejects(
      () => tinyStore.store('this string is definitely longer than ten bytes', { publish: false }),
      /exceeds max size/
    );
    rmSync(TEST_DATA_DIR + '_tiny', { recursive: true, force: true });
  });

  it('detects content type: JSON', () => {
    // Access private method via store instance
    const type = store._detectContentType({ key: 'value' });
    assert.strictEqual(type, ContentType.JSON);
  });

  it('detects content type: HTML', () => {
    const type = store._detectContentType('<!DOCTYPE html><html></html>');
    assert.strictEqual(type, ContentType.HTML);
  });

  it('LRU cache evicts oldest entry', async () => {
    const lruStore = new ContentStore({ dataDir: TEST_DATA_DIR + '_lru', cacheSize: 2 });
    await lruStore.init();
    await lruStore.store('item1', { publish: false });
    await lruStore.store('item2', { publish: false });
    await lruStore.store('item3', { publish: false });
    // Cache should have at most 2 entries
    assert.ok(lruStore.contentCache.size <= 2);
    rmSync(TEST_DATA_DIR + '_lru', { recursive: true, force: true });
  });
});

// =============================================================================
// HIGH 9.2 — Content vote signature verification
// =============================================================================

describe('ContentStore: Vote Signature Enforcement', () => {
  let store;
  const voteDir = TEST_DATA_DIR + '_vote';

  before(async () => {
    store = new ContentStore({ dataDir: voteDir, quorumSize: 2 });
    await store.init();
    // Wire up mock identity and mesh for signature verification
    store.identity = {
      identity: { nodeId: 'local-node', publicKey: 'mock-pubkey-local' },
      sign(msg) { return 'mock-sig-local'; },
      verify(msg, sig, pubKey) { return sig.startsWith('mock-sig-'); },
    };
    store.mesh = {
      peers: new Map([
        ['voter-a', { identity: { publicKey: 'mock-pubkey-voter-a' } }],
      ]),
      networkId: 'test-net',
    };
    store.gossip = { spreadRumor() {} };
  });

  after(() => {
    rmSync(voteDir, { recursive: true, force: true });
  });

  it('rejects vote with no signature', async () => {
    // Store content first
    const result = await store.store('vote-test-content', { publish: false });
    const hash = result.hash;

    // Attempt a vote with no signature
    await store._handleContentGossip({
      type: 'content_vote',
      hash,
      nodeId: 'voter-a',
      vote: 'valid',
      // no signature
    }, 'voter-a');

    const meta = store.getMeta(hash);
    assert.ok(!meta.consensusProof || meta.consensusProof.validators.length === 0,
      'Vote without signature should NOT be accepted');
  });

  it('rejects vote from unknown node (no pubkey)', async () => {
    const result = await store.store('vote-test-content-2', { publish: false });
    const hash = result.hash;

    await store._handleContentGossip({
      type: 'content_vote',
      hash,
      nodeId: 'totally-unknown-node',
      vote: 'valid',
      signature: 'mock-sig-unknown',
    }, 'totally-unknown-node');

    const meta = store.getMeta(hash);
    assert.ok(!meta.consensusProof || meta.consensusProof.validators.length === 0,
      'Vote from unknown node should NOT be accepted');
  });

  it('rejects vote with invalid signature', async () => {
    const result = await store.store('vote-test-content-3', { publish: false });
    const hash = result.hash;

    // Override verify to reject this bad sig
    const origVerify = store.identity.verify;
    store.identity.verify = (msg, sig, pk) => sig !== 'forged-signature';

    await store._handleContentGossip({
      type: 'content_vote',
      hash,
      nodeId: 'voter-a',
      vote: 'valid',
      signature: 'forged-signature',
    }, 'voter-a');

    store.identity.verify = origVerify;

    const meta = store.getMeta(hash);
    assert.ok(!meta.consensusProof || meta.consensusProof.validators.length === 0,
      'Vote with invalid signature should NOT be accepted');
  });

  it('accepts vote with valid signature from known peer', async () => {
    const result = await store.store('vote-test-content-4', { publish: false });
    const hash = result.hash;

    await store._handleContentGossip({
      type: 'content_vote',
      hash,
      nodeId: 'voter-a',
      vote: 'valid',
      signature: 'mock-sig-voter-a',
      timestamp: Date.now(),
    }, 'voter-a');

    const meta = store.getMeta(hash);
    assert.ok(meta.consensusProof, 'ConsensusProof should exist');
    assert.strictEqual(meta.consensusProof.validators.length, 1, 'Valid vote should be accepted');
    assert.strictEqual(meta.consensusProof.validators[0].nodeId, 'voter-a');
  });
});
