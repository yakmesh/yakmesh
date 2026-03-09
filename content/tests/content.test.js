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
 * Content Module Tests — ContentStore, ContentMetadata, computeContentHash
 * 
 * Content integrity = SHA3-256 hash match.
 * Content authorship = publisher ML-DSA-65 signature.
 * No voting. No quorum. No ConsensusProof.
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
    assert.strictEqual(ContentStatus.ANNOUNCED, 'announced');
    assert.strictEqual(ContentStatus.VERIFIED, 'verified');
  });

  it('does NOT have voting-era statuses', () => {
    assert.strictEqual(ContentStatus.PENDING, undefined, 'PENDING was removed (voting artifact)');
    assert.strictEqual(ContentStatus.REJECTED, undefined, 'REJECTED was removed (voting artifact)');
  });
});

// =============================================================================
// No ConsensusProof tests — voting/quorum system was removed.
// Content integrity = SHA3-256 hash match.
// Content authorship = publisher ML-DSA-65 signature.
// =============================================================================

// =============================================================================
// ContentStore — filesystem-backed content storage
// =============================================================================

describe('ContentStore', () => {
  let store;

  before(async () => {
    store = new ContentStore({ dataDir: TEST_DATA_DIR });
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
// Content Integrity Verification — hash + publisher signature
// Replaces the old voting/quorum system. Math, not votes.
// =============================================================================

describe('ContentStore: Integrity Verification', () => {
  let store;
  const integrityDir = TEST_DATA_DIR + '_integrity';

  before(async () => {
    store = new ContentStore({ dataDir: integrityDir });
    await store.init();
    // Wire up mock identity and mesh for signature verification
    store.identity = {
      identity: { nodeId: 'local-node', publicKey: 'mock-pubkey-local' },
      sign(msg) { return 'mock-sig-' + msg.slice(0, 8); },
      verify(msg, sig, pubKey) { return sig === 'mock-sig-' + msg.slice(0, 8); },
    };
    store.mesh = {
      peers: new Map([
        ['publisher-a', { identity: { publicKey: 'mock-pubkey-publisher-a' } }],
      ]),
      networkId: 'test-net',
    };
    store.gossip = { spreadRumor() {} };
  });

  after(() => {
    rmSync(integrityDir, { recursive: true, force: true });
  });

  it('content_response with valid hash + publisher sig → VERIFIED', async () => {
    const content = 'integrity test content';
    const hash = computeContentHash(content);
    const contentBase64 = Buffer.from(content, 'utf8').toString('base64');
    const publisherSig = 'mock-sig-' + hash.slice(0, 8);

    await store._handleContentGossip({
      type: 'content_response',
      hash,
      content: contentBase64,
      meta: {
        contentType: 'text/plain',
        size: Buffer.byteLength(content),
        publishedBy: 'publisher-a',
        publisherSignature: publisherSig,
      },
      timestamp: Date.now(),
    }, 'publisher-a');

    const meta = store.getMeta(hash);
    assert.strictEqual(meta.status, ContentStatus.VERIFIED, 'Valid hash + sig should be VERIFIED');
    assert.strictEqual(meta.publisherSignature, publisherSig);
  });

  it('content_response with bad hash → rejected (not stored)', async () => {
    const content = 'legitimate content';
    const hash = computeContentHash(content);
    const tamperedContent = Buffer.from('tampered content', 'utf8').toString('base64');

    await store._handleContentGossip({
      type: 'content_response',
      hash,
      content: tamperedContent,  // Does NOT match hash
      meta: {
        contentType: 'text/plain',
        size: 16,
        publishedBy: 'publisher-a',
        publisherSignature: 'mock-sig-' + hash.slice(0, 8),
      },
      timestamp: Date.now(),
    }, 'publisher-a');

    // Content should NOT be stored (hash mismatch)
    assert.strictEqual(store.has(hash), false, 'Tampered content should not be stored');
  });

  it('content_response with no publisher sig → ANNOUNCED (not VERIFIED)', async () => {
    const content = 'unsigned content test';
    const hash = computeContentHash(content);
    const contentBase64 = Buffer.from(content, 'utf8').toString('base64');

    await store._handleContentGossip({
      type: 'content_response',
      hash,
      content: contentBase64,
      meta: {
        contentType: 'text/plain',
        size: Buffer.byteLength(content),
        publishedBy: 'publisher-a',
        // No publisherSignature
      },
      timestamp: Date.now(),
    }, 'publisher-a');

    const meta = store.getMeta(hash);
    assert.strictEqual(meta.status, ContentStatus.ANNOUNCED,
      'Content without publisher sig should be ANNOUNCED, not VERIFIED');
  });

  it('content_response with unknown publisher → ANNOUNCED (not VERIFIED)', async () => {
    const content = 'unknown publisher content';
    const hash = computeContentHash(content);
    const contentBase64 = Buffer.from(content, 'utf8').toString('base64');

    await store._handleContentGossip({
      type: 'content_response',
      hash,
      content: contentBase64,
      meta: {
        contentType: 'text/plain',
        size: Buffer.byteLength(content),
        publishedBy: 'totally-unknown-publisher',
        publisherSignature: 'mock-sig-' + hash.slice(0, 8),
      },
      timestamp: Date.now(),
    }, 'some-relay');

    const meta = store.getMeta(hash);
    assert.strictEqual(meta.status, ContentStatus.ANNOUNCED,
      'Content from unknown publisher should be ANNOUNCED (cannot verify sig)');
  });

  it('content_response with invalid publisher sig → ANNOUNCED (not VERIFIED)', async () => {
    const content = 'forged sig content';
    const hash = computeContentHash(content);
    const contentBase64 = Buffer.from(content, 'utf8').toString('base64');

    await store._handleContentGossip({
      type: 'content_response',
      hash,
      content: contentBase64,
      meta: {
        contentType: 'text/plain',
        size: Buffer.byteLength(content),
        publishedBy: 'publisher-a',
        publisherSignature: 'forged-signature-definitely-wrong',
      },
      timestamp: Date.now(),
    }, 'publisher-a');

    const meta = store.getMeta(hash);
    assert.strictEqual(meta.status, ContentStatus.ANNOUNCED,
      'Content with invalid publisher sig should be ANNOUNCED, not VERIFIED');
  });

  it('publish() sets status to ANNOUNCED and signs content hash', async () => {
    const result = await store.store('publish test content', { publish: false });
    const hash = result.hash;

    await store.publish(hash);

    const meta = store.getMeta(hash);
    assert.strictEqual(meta.status, ContentStatus.ANNOUNCED, 'Published content should be ANNOUNCED');
    assert.ok(meta.publisherSignature, 'Publisher signature should be set');
    assert.ok(meta.publisherSignature.startsWith('mock-sig-'), 'Signature should be from identity.sign()');
  });

  it('getWithProof() returns verified flag without consensus proof', async () => {
    const result = await store.store('getWithProof test', { publish: false });
    const full = store.getWithProof(result.hash);
    assert.ok(full, 'Should return result');
    assert.ok(full.content, 'Should have content');
    assert.ok(full.meta, 'Should have meta');
    assert.strictEqual(full.verified, false, 'LOCAL content is not verified');
    assert.strictEqual(full.proof, undefined, 'No consensus proof object should exist');
  });

  it('no content_vote or content_validate handlers exist', async () => {
    // These gossip types were removed (voting system eliminated)
    // Sending them should be a no-op — no crash, no state change
    const result = await store.store('vote handler removed test', { publish: false });
    const hash = result.hash;

    // content_vote should be silently ignored (no case match)
    await store._handleContentGossip({
      type: 'content_vote',
      hash,
      nodeId: 'publisher-a',
      vote: 'valid',
      signature: 'mock-sig-whatever',
    }, 'publisher-a');

    const meta = store.getMeta(hash);
    assert.strictEqual(meta.status, ContentStatus.LOCAL,
      'content_vote should be silently ignored (voting system removed)');

    // content_validate should also be silently ignored
    await store._handleContentGossip({
      type: 'content_validate',
      hash,
      contentType: 'text/plain',
    }, 'publisher-a');

    const meta2 = store.getMeta(hash);
    assert.strictEqual(meta2.status, ContentStatus.LOCAL,
      'content_validate should be silently ignored (voting system removed)');
  });
});
