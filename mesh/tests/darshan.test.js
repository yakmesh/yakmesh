/**
 * DARSHAN Protocol Tests
 * 
 * Tests for the content streaming protocol.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  DARSHAN_CONFIG,
  DarshanContent,
  DarshanStream,
  DarshanAttestation,
  DarshanRequest,
  DarshanChunk,
  DarshanGateway,
  DarshanViewer,
  DarshanMount,
} from '../darshan.js';

// ═══════════════════════════════════════════════════════════════════════════════
// MOCK IDENTITY
// ═══════════════════════════════════════════════════════════════════════════════

function createMockIdentity(nodeId = 'node-' + Math.random().toString(36).slice(2)) {
  return {
    identity: {
      nodeId,
      secretKey: new Uint8Array(32).fill(1),
      publicKey: new Uint8Array(32).fill(2),
    },
    nodeId,
  };
}

function createMockFileReader(files = {}) {
  return {
    async read(path) {
      if (files[path]) {
        return Buffer.from(files[path]);
      }
      throw new Error('File not found: ' + path);
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('DARSHAN_CONFIG', () => {
  it('is frozen', () => {
    expect(Object.isFrozen(DARSHAN_CONFIG)).toBe(true);
  });
  
  it('has correct default chunk size', () => {
    expect(DARSHAN_CONFIG.defaultChunkSize).toBe(64 * 1024);
  });
  
  it('has quality presets', () => {
    expect(DARSHAN_CONFIG.qualityPresets.ORIGINAL).toBe('original');
    expect(DARSHAN_CONFIG.qualityPresets.HIGH).toBe('high');
    expect(DARSHAN_CONFIG.qualityPresets.MEDIUM).toBe('medium');
    expect(DARSHAN_CONFIG.qualityPresets.LOW).toBe('low');
  });
  
  it('has content types', () => {
    expect(DARSHAN_CONFIG.contentTypes.VIDEO).toBe('video');
    expect(DARSHAN_CONFIG.contentTypes.AUDIO).toBe('audio');
    expect(DARSHAN_CONFIG.contentTypes.IMAGE).toBe('image');
    expect(DARSHAN_CONFIG.contentTypes.DOCUMENT).toBe('document');
    expect(DARSHAN_CONFIG.contentTypes.STREAM).toBe('stream');
  });
  
  it('has permissions', () => {
    expect(DARSHAN_CONFIG.permissions.VIEW).toBe('view');
    expect(DARSHAN_CONFIG.permissions.DOWNLOAD).toBe('download');
    expect(DARSHAN_CONFIG.permissions.SHARE).toBe('share');
  });
  
  it('has message types for streaming', () => {
    expect(DARSHAN_CONFIG.messageTypes.STREAM_REQUEST).toBe('darshan:stream:request');
    expect(DARSHAN_CONFIG.messageTypes.STREAM_CHUNK).toBe('darshan:stream:chunk');
    expect(DARSHAN_CONFIG.messageTypes.STREAM_END).toBe('darshan:stream:end');
  });
  
  it('has message types for attestation', () => {
    expect(DARSHAN_CONFIG.messageTypes.VIEW_START).toBe('darshan:view:start');
    expect(DARSHAN_CONFIG.messageTypes.VIEW_HEARTBEAT).toBe('darshan:view:heartbeat');
    expect(DARSHAN_CONFIG.messageTypes.VIEW_END).toBe('darshan:view:end');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN CONTENT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('DarshanContent', () => {
  it('creates content with defaults', () => {
    const content = new DarshanContent({
      hostNodeId: 'host-123',
      path: '/videos/test.mp4',
    });
    
    expect(content.contentId).toBeDefined();
    expect(content.hostNodeId).toBe('host-123');
    expect(content.path).toBe('/videos/test.mp4');
    expect(content.contentType).toBe(DARSHAN_CONFIG.contentTypes.ANY);
    expect(content.permissions).toEqual([DARSHAN_CONFIG.permissions.VIEW]);
  });
  
  it('generates unique content IDs', () => {
    const c1 = new DarshanContent({ hostNodeId: 'h1', path: '/a' });
    const c2 = new DarshanContent({ hostNodeId: 'h1', path: '/b' });
    expect(c1.contentId).not.toBe(c2.contentId);
  });
  
  it('validates required fields', () => {
    const content = new DarshanContent({});
    const result = content.validate();
    
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('hostNodeId required');
    expect(result.errors).toContain('path required');
  });
  
  it('validates path length', () => {
    const content = new DarshanContent({
      hostNodeId: 'host',
      path: 'x'.repeat(600),
    });
    const result = content.validate();
    
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('path too long');
  });
  
  it('validates content type', () => {
    const content = new DarshanContent({
      hostNodeId: 'host',
      path: '/test',
      contentType: 'invalid-type',
    });
    const result = content.validate();
    
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('invalid contentType');
  });
  
  it('returns public metadata without path', () => {
    const content = new DarshanContent({
      hostNodeId: 'host-123',
      path: '/secret/path/video.mp4',
      name: 'My Video',
    });
    
    const pub = content.getPublicMetadata();
    
    expect(pub.name).toBe('My Video');
    expect(pub.contentId).toBeDefined();
    expect(pub.path).toBeUndefined();
  });
  
  it('serializes and deserializes', () => {
    const content = new DarshanContent({
      hostNodeId: 'host',
      path: '/test.mp4',
      name: 'Test Video',
      contentType: 'video',
      size: 1024000,
      duration: 120,
    });
    
    const json = content.toJSON();
    const restored = DarshanContent.fromJSON(json);
    
    expect(restored.contentId).toBe(content.contentId);
    expect(restored.name).toBe('Test Video');
    expect(restored.size).toBe(1024000);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN STREAM TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('DarshanStream', () => {
  it('creates stream with defaults', () => {
    const stream = new DarshanStream({
      contentId: 'content-123',
      viewerId: 'viewer-456',
      hostId: 'host-789',
    });
    
    expect(stream.streamId).toBeDefined();
    expect(stream.state).toBe('idle');
    expect(stream.position).toBe(0);
    expect(stream.chunkSize).toBe(DARSHAN_CONFIG.defaultChunkSize);
  });
  
  it('generates unique stream IDs', () => {
    const s1 = new DarshanStream({});
    const s2 = new DarshanStream({});
    expect(s1.streamId).not.toBe(s2.streamId);
  });
  
  it('calculates chunk ranges', () => {
    const stream = new DarshanStream({ chunkSize: 1024 });
    
    const range = stream.getChunkRange(2000, 3500);
    expect(range.chunkStart).toBe(1);  // 2000 / 1024 = 1.95
    expect(range.chunkEnd).toBe(3);    // 3500 / 1024 = 3.42
  });
  
  it('requests byte ranges', () => {
    const stream = new DarshanStream({ chunkSize: 1024 });
    
    const needed = stream.requestRange(0, 2047);
    expect(needed).toEqual([0, 1024]);
  });
  
  it('tracks pending requests', () => {
    const stream = new DarshanStream({ chunkSize: 1024 });
    
    stream.requestRange(0, 1023);
    expect(stream.pendingRequests.has(0)).toBe(true);
    
    stream.receiveChunk(0, Buffer.alloc(1024));
    expect(stream.pendingRequests.has(0)).toBe(false);
  });
  
  it('stores received chunks', () => {
    const stream = new DarshanStream({ chunkSize: 1024 });
    const data = Buffer.from('hello world');
    
    const success = stream.receiveChunk(0, data);
    expect(success).toBe(true);
    expect(stream.chunks.has(0)).toBe(true);
    expect(stream.bytesReceived).toBe(11);
  });
  
  it('calls onProgress on chunk receive', () => {
    const onProgress = vi.fn();
    const stream = new DarshanStream({
      chunkSize: 1024,
      size: 2048,
      onProgress,
    });
    
    stream.receiveChunk(0, Buffer.alloc(1024));
    
    expect(onProgress).toHaveBeenCalledWith({
      bytesReceived: 1024,
      bytesTotal: 2048,
      percent: 50,
    });
  });
  
  it('seeks to position', () => {
    const stream = new DarshanStream({ size: 10000 });
    
    expect(stream.seek(5000)).toBe(true);
    expect(stream.position).toBe(5000);
    
    expect(stream.seek(-1)).toBe(false);
    expect(stream.seek(10001)).toBe(false);
  });
  
  it('pauses and resumes', () => {
    const stream = new DarshanStream({});
    stream.state = 'streaming';
    
    stream.pause();
    expect(stream.state).toBe('paused');
    
    stream.resume();
    expect(stream.state).toBe('streaming');
  });
  
  it('ends stream', () => {
    const onEnd = vi.fn();
    const stream = new DarshanStream({ onEnd });
    stream.startTime = Date.now() - 1000;
    
    stream.end();
    
    expect(stream.state).toBe('ended');
    expect(stream.endTime).toBeDefined();
    expect(onEnd).toHaveBeenCalled();
  });
  
  it('destroys cleanup resources', () => {
    const stream = new DarshanStream({});
    stream.receiveChunk(0, Buffer.alloc(100));
    stream.requestRange(1024, 2047);
    
    stream.destroy();
    
    expect(stream.chunks.size).toBe(0);
    expect(stream.pendingRequests.size).toBe(0);
  });
  
  it('returns stats', () => {
    const stream = new DarshanStream({
      contentId: 'c1',
      size: 10000,
    });
    stream.state = 'streaming';
    stream.bytesReceived = 5000;
    
    const stats = stream.getStats();
    
    expect(stats.streamId).toBeDefined();
    expect(stats.state).toBe('streaming');
    expect(stats.bytesReceived).toBe(5000);
    expect(stats.bytesTotal).toBe(10000);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN ATTESTATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('DarshanAttestation', () => {
  it('creates attestation with defaults', () => {
    const attest = new DarshanAttestation({
      contentId: 'content-123',
      viewerId: 'viewer-456',
      hostId: 'host-789',
      sessionId: 'session-abc',
    });
    
    expect(attest.attestationId).toBeDefined();
    expect(attest.contentId).toBe('content-123');
    expect(attest.startedAt).toBeDefined();
    expect(attest.bytesViewed).toBe(0);
  });
  
  it('generates unique IDs', () => {
    const a1 = new DarshanAttestation({});
    const a2 = new DarshanAttestation({});
    expect(a1.attestationId).not.toBe(a2.attestationId);
  });
  
  it('gets signable payload', () => {
    const attest = new DarshanAttestation({
      contentId: 'c1',
      viewerId: 'v1',
      hostId: 'h1',
      sessionId: 's1',
    });
    
    const payload = attest.getSignablePayload();
    const parsed = JSON.parse(payload);
    
    expect(parsed.contentId).toBe('c1');
    expect(parsed.viewerId).toBe('v1');
    expect(parsed.hostId).toBe('h1');
  });
  
  it('updates during viewing', () => {
    const attest = new DarshanAttestation({});
    
    attest.update({
      bytesViewed: 50000,
      percentViewed: 75,
      seekCount: 3,
    });
    
    expect(attest.bytesViewed).toBe(50000);
    expect(attest.percentViewed).toBe(75);
    expect(attest.seekCount).toBe(3);
  });
  
  it('finalizes with end time', () => {
    const attest = new DarshanAttestation({});
    const startTime = attest.startedAt;
    
    // Wait a bit to ensure duration > 0
    attest.finalize();
    
    expect(attest.endedAt).toBeDefined();
    expect(attest.endedAt).toBeGreaterThanOrEqual(startTime);
    expect(attest.duration).toBeDefined();
  });
  
  it('checks completeness', () => {
    const attest = new DarshanAttestation({});
    
    expect(attest.isComplete()).toBe(false);
    
    attest.viewerSignature = 'sig1';
    expect(attest.isComplete()).toBe(false);
    
    attest.hostSignature = 'sig2';
    expect(attest.isComplete()).toBe(false);
    
    attest.endedAt = Date.now();
    expect(attest.isComplete()).toBe(true);
  });
  
  it('serializes and deserializes', () => {
    const attest = new DarshanAttestation({
      contentId: 'c1',
      viewerId: 'v1',
      hostId: 'h1',
      sessionId: 's1',
      bytesViewed: 1000,
      percentViewed: 50,
    });
    
    const json = attest.toJSON();
    const restored = DarshanAttestation.fromJSON(json);
    
    expect(restored.attestationId).toBe(attest.attestationId);
    expect(restored.bytesViewed).toBe(1000);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN REQUEST TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('DarshanRequest', () => {
  it('creates request with defaults', () => {
    const req = new DarshanRequest({
      contentId: 'content-123',
      viewerId: 'viewer-456',
    });
    
    expect(req.requestId).toBeDefined();
    expect(req.type).toBe(DARSHAN_CONFIG.messageTypes.STREAM_REQUEST);
    expect(req.startByte).toBe(0);
    expect(req.endByte).toBeNull();
  });
  
  it('creates stream request via factory', () => {
    const req = DarshanRequest.streamRequest({
      contentId: 'c1',
      viewerId: 'v1',
      startByte: 1000,
      endByte: 5000,
    });
    
    expect(req.type).toBe(DARSHAN_CONFIG.messageTypes.STREAM_REQUEST);
    expect(req.startByte).toBe(1000);
    expect(req.endByte).toBe(5000);
  });
  
  it('creates seek request', () => {
    const req = DarshanRequest.seekRequest({
      contentId: 'c1',
      viewerId: 'v1',
      startByte: 50000,
    });
    
    expect(req.type).toBe(DARSHAN_CONFIG.messageTypes.SEEK);
  });
  
  it('validates required fields', () => {
    const req = new DarshanRequest({});
    const result = req.validate();
    
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('contentId required');
    expect(result.errors).toContain('viewerId required');
  });
  
  it('validates byte ranges', () => {
    const req = new DarshanRequest({
      contentId: 'c1',
      viewerId: 'v1',
      startByte: 1000,
      endByte: 500,
    });
    
    const result = req.validate();
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('endByte must be >= startByte');
  });
  
  it('serializes and deserializes', () => {
    const req = new DarshanRequest({
      contentId: 'c1',
      viewerId: 'v1',
      quality: 'high',
    });
    
    const json = req.toJSON();
    const restored = DarshanRequest.fromJSON(json);
    
    expect(restored.requestId).toBe(req.requestId);
    expect(restored.quality).toBe('high');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN CHUNK TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('DarshanChunk', () => {
  it('creates chunk with data', () => {
    const chunk = new DarshanChunk({
      streamId: 's1',
      contentId: 'c1',
      offset: 1024,
      data: Buffer.from('hello'),
    });
    
    expect(chunk.streamId).toBe('s1');
    expect(chunk.offset).toBe(1024);
    expect(chunk.data.toString()).toBe('hello');
  });
  
  it('creates from buffer with auto-hash', () => {
    const data = Buffer.from('test content');
    const chunk = DarshanChunk.fromBuffer(data, {
      streamId: 's1',
      contentId: 'c1',
      offset: 0,
    });
    
    expect(chunk.data).toEqual(data);
    expect(chunk.hash).toBeDefined();
    expect(chunk.hash.length).toBe(64);
  });
  
  it('verifies chunk integrity', () => {
    const data = Buffer.from('original content');
    const chunk = DarshanChunk.fromBuffer(data, {});
    
    expect(chunk.verify()).toBe(true);
    
    // Corrupt data
    chunk.data = Buffer.from('modified content');
    expect(chunk.verify()).toBe(false);
  });
  
  it('serializes to base64', () => {
    const chunk = DarshanChunk.fromBuffer(Buffer.from('test'), {
      streamId: 's1',
    });
    
    const json = chunk.toJSON();
    expect(json.data).toBe(Buffer.from('test').toString('base64'));
    expect(json.hash).toBeDefined();
  });
  
  it('deserializes from base64', () => {
    const json = {
      streamId: 's1',
      contentId: 'c1',
      offset: 0,
      data: Buffer.from('hello').toString('base64'),
      hash: 'abc',
    };
    
    const chunk = DarshanChunk.fromJSON(json);
    expect(chunk.data.toString()).toBe('hello');
  });
  
  it('handles first and last flags', () => {
    const chunk = new DarshanChunk({
      isFirst: true,
      isLast: false,
      totalSize: 10000,
    });
    
    expect(chunk.isFirst).toBe(true);
    expect(chunk.isLast).toBe(false);
    expect(chunk.totalSize).toBe(10000);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN GATEWAY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('DarshanGateway', () => {
  let gateway;
  let mockIdentity;
  let mockFileReader;
  
  beforeEach(() => {
    mockIdentity = createMockIdentity('host-gateway');
    mockFileReader = createMockFileReader({
      '/videos/test.mp4': 'video content here for testing',
      '/docs/readme.txt': 'readme content',
    });
    gateway = new DarshanGateway(mockIdentity, { fileReader: mockFileReader });
  });
  
  it('creates gateway with identity', () => {
    expect(gateway.nodeId).toBe('host-gateway');
    expect(gateway.contents.size).toBe(0);
    expect(gateway.streams.size).toBe(0);
  });
  
  it('registers content', async () => {
    const result = await gateway.registerContent({
      path: '/videos/test.mp4',
      name: 'Test Video',
      contentType: 'video',
    });
    
    expect(result.success).toBe(true);
    expect(result.content.name).toBe('Test Video');
    expect(result.content.hash).toBeDefined();
    expect(gateway.contents.size).toBe(1);
  });
  
  it('computes content hash on register', async () => {
    const result = await gateway.registerContent({
      path: '/videos/test.mp4',
      name: 'Test Video',
    });
    
    expect(result.content.hash).toBeDefined();
    expect(result.content.hash.length).toBe(64);
    expect(result.content.size).toBe(30);
  });
  
  it('computes chunk hashes', async () => {
    const result = await gateway.registerContent({
      path: '/videos/test.mp4',
    });
    
    expect(result.content.chunkHashes.length).toBeGreaterThan(0);
  });
  
  it('fails to register content with missing file', async () => {
    const result = await gateway.registerContent({
      path: '/nonexistent.mp4',
    });
    
    expect(result.success).toBe(false);
    expect(result.errors[0]).toContain('Failed to read content');
  });
  
  it('fails validation without required fields', () => {
    const content = new DarshanContent({});
    const result = content.validate();
    
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('hostNodeId required');
  });
  
  it('unregisters content', async () => {
    const result = await gateway.registerContent({
      path: '/videos/test.mp4',
      name: 'Test',
    });
    
    expect(gateway.unregisterContent(result.content.contentId)).toBe(true);
    expect(gateway.contents.size).toBe(0);
  });
  
  it('lists registered content', async () => {
    await gateway.registerContent({ path: '/videos/test.mp4', name: 'Video' });
    await gateway.registerContent({ path: '/docs/readme.txt', name: 'Readme' });
    
    const list = gateway.listContent();
    expect(list.length).toBe(2);
    expect(list[0].name).toBeDefined();
  });
  
  it('handles stream request for registered content', async () => {
    const reg = await gateway.registerContent({
      path: '/videos/test.mp4',
      name: 'Test',
    });
    
    const chunks = [];
    const result = await gateway.handleStreamRequest(
      { contentId: reg.content.contentId, viewerId: 'viewer-1' },
      async (chunk) => chunks.push(chunk)
    );
    
    expect(result.success).toBe(true);
    expect(result.streamId).toBeDefined();
    expect(result.attestationId).toBeDefined();
  });
  
  it('rejects request for unknown content', async () => {
    const result = await gateway.handleStreamRequest(
      { contentId: 'nonexistent', viewerId: 'viewer-1' },
      async () => {}
    );
    
    expect(result.success).toBe(false);
    expect(result.error).toBe('CONTENT_NOT_FOUND');
  });
  
  it('creates attestation on stream', async () => {
    const reg = await gateway.registerContent({
      path: '/videos/test.mp4',
      name: 'Test',
    });
    
    const result = await gateway.handleStreamRequest(
      { contentId: reg.content.contentId, viewerId: 'viewer-1' },
      async () => {}
    );
    
    const attestation = gateway.getAttestation(result.attestationId);
    expect(attestation).not.toBeNull();
    expect(attestation.viewerId).toBe('viewer-1');
  });
  
  it('returns stats', async () => {
    await gateway.registerContent({ path: '/videos/test.mp4', name: 'V' });
    
    const stats = gateway.getStats();
    expect(stats.contentRegistered).toBe(1);
    expect(stats.registeredContent).toBe(1);
  });
  
  // Exclusion (moderation) tests
  it('excludes content from listings', async () => {
    const reg = await gateway.registerContent({ path: '/videos/test.mp4', name: 'V' });
    expect(gateway.listContent().length).toBe(1);
    
    const result = gateway.excludeContent(reg.content.contentId, {
      excludedBy: 'admin-1',
      reason: 'community-guidelines',
    });
    
    expect(result.success).toBe(true);
    expect(gateway.listContent().length).toBe(0);  // Hidden from public listing
  });
  
  it('includes excluded content when requested', async () => {
    const reg = await gateway.registerContent({ path: '/videos/test.mp4', name: 'V' });
    gateway.excludeContent(reg.content.contentId);
    
    const publicList = gateway.listContent();
    const adminList = gateway.listContent({ includeExcluded: true });
    
    expect(publicList.length).toBe(0);
    expect(adminList.length).toBe(1);
    expect(adminList[0].excluded).toBe(true);
  });
  
  it('reinstates excluded content', async () => {
    const reg = await gateway.registerContent({ path: '/videos/test.mp4', name: 'V' });
    gateway.excludeContent(reg.content.contentId);
    expect(gateway.listContent().length).toBe(0);
    
    const result = gateway.reinstateContent(reg.content.contentId);
    expect(result.success).toBe(true);
    expect(gateway.listContent().length).toBe(1);
  });
  
  it('fails to exclude non-existent content', () => {
    const result = gateway.excludeContent('nonexistent');
    expect(result.success).toBe(false);
    expect(result.error).toBe('CONTENT_NOT_FOUND');
  });
  
  it('fails to reinstate non-excluded content', async () => {
    const reg = await gateway.registerContent({ path: '/videos/test.mp4', name: 'V' });
    const result = gateway.reinstateContent(reg.content.contentId);
    expect(result.success).toBe(false);
    expect(result.error).toBe('NOT_EXCLUDED');
  });
  
  it('checks if content is excluded', async () => {
    const reg = await gateway.registerContent({ path: '/videos/test.mp4', name: 'V' });
    expect(gateway.isExcluded(reg.content.contentId)).toBe(false);
    
    gateway.excludeContent(reg.content.contentId);
    expect(gateway.isExcluded(reg.content.contentId)).toBe(true);
  });
  
  it('lists all exclusions', async () => {
    const reg1 = await gateway.registerContent({ path: '/videos/test.mp4', name: 'V1' });
    const reg2 = await gateway.registerContent({ path: '/docs/readme.txt', name: 'V2' });
    
    gateway.excludeContent(reg1.content.contentId, { reason: 'spam' });
    gateway.excludeContent(reg2.content.contentId, { reason: 'abuse' });
    
    const exclusions = gateway.listExclusions();
    expect(exclusions.length).toBe(2);
    expect(exclusions.map(e => e.reason)).toContain('spam');
    expect(exclusions.map(e => e.reason)).toContain('abuse');
  });
  
  it('includes exclusion count in stats', async () => {
    const reg = await gateway.registerContent({ path: '/videos/test.mp4', name: 'V' });
    gateway.excludeContent(reg.content.contentId);
    
    const stats = gateway.getStats();
    expect(stats.excludedContent).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN VIEWER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('DarshanViewer', () => {
  let viewer;
  let mockIdentity;
  let sentMessages;
  
  beforeEach(() => {
    mockIdentity = createMockIdentity('viewer-node');
    sentMessages = [];
    viewer = new DarshanViewer(mockIdentity, {
      sendMessage: (hostId, msg) => sentMessages.push({ hostId, msg }),
    });
  });
  
  it('creates viewer with identity', () => {
    expect(viewer.nodeId).toBe('viewer-node');
    expect(viewer.streams.size).toBe(0);
    expect(viewer.knownContent.size).toBe(0);
  });
  
  it('starts stream', async () => {
    const stream = await viewer.startStream('host-1', 'content-1', {
      contentInfo: { contentId: 'content-1', size: 1000 },
    });
    
    expect(stream).toBeDefined();
    expect(stream.streamId).toBeDefined();
    expect(stream.contentId).toBe('content-1');
    expect(stream.state).toBe('requesting');
    expect(viewer.streams.size).toBe(1);
  });
  
  it('sends stream request message', async () => {
    await viewer.startStream('host-1', 'content-1', {
      contentInfo: { contentId: 'content-1', size: 1000 },
    });
    
    expect(sentMessages.length).toBe(1);
    expect(sentMessages[0].hostId).toBe('host-1');
    expect(sentMessages[0].msg.type).toBe(DARSHAN_CONFIG.messageTypes.STREAM_REQUEST);
  });
  
  it('handles stream response', async () => {
    const stream = await viewer.startStream('host-1', 'content-1', {});
    
    viewer.handleStreamResponse({
      streamId: stream.streamId,
      success: true,
      attestationId: 'attest-1',
    });
    
    expect(stream.state).toBe('streaming');
    expect(stream.attestationId).toBe('attest-1');
  });
  
  it('handles stream error response', async () => {
    const onError = vi.fn();
    const stream = await viewer.startStream('host-1', 'content-1', { onError });
    
    viewer.handleStreamResponse({
      streamId: stream.streamId,
      success: false,
      error: 'ACCESS_DENIED',
    });
    
    expect(stream.state).toBe('error');
    expect(onError).toHaveBeenCalledWith('ACCESS_DENIED');
  });
  
  it('handles incoming chunk', async () => {
    const onChunk = vi.fn();
    const stream = await viewer.startStream('host-1', 'content-1', {
      contentInfo: { contentId: 'content-1', size: 1000 },
      onChunk,
    });
    stream.state = 'streaming';
    
    const chunkData = DarshanChunk.fromBuffer(Buffer.from('hello'), {
      streamId: stream.streamId,
      contentId: 'content-1',
      offset: 0,
    }).toJSON();
    
    viewer.handleChunk(chunkData);
    
    expect(onChunk).toHaveBeenCalled();
    expect(stream.bytesReceived).toBe(5);
  });
  
  it('rejects invalid chunk', async () => {
    const stream = await viewer.startStream('host-1', 'content-1', {});
    stream.state = 'streaming';
    
    const events = [];
    viewer.on('chunk:invalid', (e) => events.push(e));
    
    viewer.handleChunk({
      streamId: stream.streamId,
      contentId: 'content-1',
      offset: 0,
      data: Buffer.from('hello').toString('base64'),
      hash: 'wrong-hash',
    });
    
    expect(events.length).toBe(1);
  });
  
  it('seeks within stream', async () => {
    const stream = await viewer.startStream('host-1', 'content-1', {
      contentInfo: { size: 10000 },
    });
    
    const result = viewer.seek(stream.streamId, 5000);
    
    expect(result).toBe(true);
    expect(stream.position).toBe(5000);
    expect(sentMessages[sentMessages.length - 1].msg.type).toBe(DARSHAN_CONFIG.messageTypes.SEEK);
  });
  
  it('pauses stream', async () => {
    const stream = await viewer.startStream('host-1', 'content-1', {});
    stream.state = 'streaming';
    
    viewer.pause(stream.streamId);
    
    expect(stream.state).toBe('paused');
    expect(sentMessages[sentMessages.length - 1].msg.type).toBe(DARSHAN_CONFIG.messageTypes.PAUSE);
  });
  
  it('resumes stream', async () => {
    const stream = await viewer.startStream('host-1', 'content-1', {});
    stream.state = 'paused';
    
    viewer.resume(stream.streamId);
    
    expect(stream.state).toBe('streaming');
  });
  
  it('ends stream', async () => {
    const stream = await viewer.startStream('host-1', 'content-1', {});
    
    viewer.endStream(stream.streamId);
    
    expect(stream.state).toBe('ended');
    expect(viewer.streams.size).toBe(0);
    expect(sentMessages[sentMessages.length - 1].msg.type).toBe(DARSHAN_CONFIG.messageTypes.STREAM_END);
  });
  
  it('gets stream for content', async () => {
    const stream = await viewer.startStream('host-1', 'content-1', {});
    
    const found = viewer.getStreamForContent('content-1');
    expect(found).toBe(stream);
  });
  
  it('returns stats', async () => {
    await viewer.startStream('host-1', 'content-1', {});
    
    const stats = viewer.getStats();
    expect(stats.streamsOpened).toBe(1);
    expect(stats.activeStreams).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DARSHAN MOUNT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('DarshanMount', () => {
  let mount;
  let viewer;
  let mockIdentity;
  
  beforeEach(() => {
    mockIdentity = createMockIdentity('mount-node');
    viewer = new DarshanViewer(mockIdentity, {
      sendMessage: () => {},
    });
    mount = new DarshanMount({
      mountPoint: '/yak',
      viewer,
    });
  });
  
  it('creates mount with defaults', () => {
    expect(mount.mountPoint).toBe('/yak');
    expect(mount.mounted).toBe(false);
    expect(mount.virtualFs.size).toBe(0);
  });
  
  it('mounts virtual filesystem', async () => {
    const events = [];
    mount.on('mount', (e) => events.push(e));
    
    await mount.mount();
    
    expect(mount.mounted).toBe(true);
    expect(events.length).toBe(1);
    expect(events[0].mountPoint).toBe('/yak');
  });
  
  it('throws on double mount', async () => {
    await mount.mount();
    
    await expect(mount.mount()).rejects.toThrow('Already mounted');
  });
  
  it('unmounts virtual filesystem', async () => {
    await mount.mount();
    
    const result = await mount.unmount();
    
    expect(result).toBe(true);
    expect(mount.mounted).toBe(false);
  });
  
  it('adds content to virtual filesystem', () => {
    const content = new DarshanContent({
      contentId: 'c1',
      hostNodeId: 'host-1',
      name: 'video.mp4',
      path: '/local/path',
      size: 1000,
    });
    
    const path = mount.addContent('host-1', content);
    
    expect(path).toContain('video.mp4');
    expect(mount.virtualFs.has(path)).toBe(true);
  });
  
  it('creates parent directories', () => {
    const content = new DarshanContent({
      contentId: 'c1',
      hostNodeId: 'host-1',
      name: 'file.txt',
      path: '/local',
    });
    
    mount.addContent('host-1', content, '/yak/host-1/subdir/file.txt');
    
    expect(mount.virtualFs.has('/yak')).toBe(true);
    expect(mount.virtualFs.has('/yak/host-1')).toBe(true);
    expect(mount.virtualFs.has('/yak/host-1/subdir')).toBe(true);
  });
  
  it('removes content from virtual filesystem', () => {
    const content = new DarshanContent({
      contentId: 'c1',
      hostNodeId: 'h1',
      name: 'f.txt',
      path: '/p',
    });
    
    const path = mount.addContent('h1', content);
    expect(mount.removeContent(path)).toBe(true);
    expect(mount.virtualFs.has(path)).toBe(false);
  });
  
  it('lists directory contents', () => {
    const c1 = new DarshanContent({ contentId: 'c1', hostNodeId: 'h1', name: 'a.txt', path: '/p' });
    const c2 = new DarshanContent({ contentId: 'c2', hostNodeId: 'h1', name: 'b.txt', path: '/p' });
    
    mount.addContent('h1', c1, '/yak/dir/a.txt');
    mount.addContent('h1', c2, '/yak/dir/b.txt');
    
    const entries = mount.readdir('/yak/dir');
    expect(entries).toContain('a.txt');
    expect(entries).toContain('b.txt');
  });
  
  it('returns null for non-existent directory', () => {
    expect(mount.readdir('/nonexistent')).toBeNull();
  });
  
  it('gets file stats', () => {
    const content = new DarshanContent({
      contentId: 'c1',
      hostNodeId: 'h1',
      name: 'test.mp4',
      path: '/p',
      size: 5000,
    });
    
    const path = mount.addContent('h1', content);
    const stats = mount.stat(path);
    
    expect(stats.type).toBe('file');
    expect(stats.size).toBe(5000);
    expect(stats.contentId).toBe('c1');
  });
  
  it('returns null stats for non-existent path', () => {
    expect(mount.stat('/nonexistent')).toBeNull();
  });
  
  it('opens file and returns handle', async () => {
    await mount.mount();
    
    const content = new DarshanContent({
      contentId: 'c1',
      hostNodeId: 'h1',
      name: 'test.txt',
      path: '/p',
      size: 100,
    });
    
    mount.addContent('h1', content);
    
    // Mock the viewer's startStream
    vi.spyOn(viewer, 'startStream').mockResolvedValue(new DarshanStream({
      contentId: 'c1',
      size: 100,
    }));
    
    const path = '/yak/h1/test.txt';
    mount.virtualFs.set(path, {
      type: 'file',
      contentId: 'c1',
      hostId: 'h1',
      content,
      size: 100,
    });
    
    const handle = await mount.open(path);
    
    expect(handle).toBeDefined();
    expect(mount.handles.size).toBe(1);
  });
  
  it('throws on opening non-existent file', async () => {
    await mount.mount();
    
    await expect(mount.open('/yak/nope.txt')).rejects.toThrow('File not found');
  });
  
  it('closes file handle', async () => {
    await mount.mount();
    
    const content = new DarshanContent({
      contentId: 'c1',
      hostNodeId: 'h1',
      name: 'test.txt',
      path: '/p',
    });
    
    const path = '/yak/h1/test.txt';
    mount.virtualFs.set(path, {
      type: 'file',
      contentId: 'c1',
      hostId: 'h1',
      content,
      size: 100,
    });
    
    const mockStream = new DarshanStream({ contentId: 'c1' });
    vi.spyOn(viewer, 'startStream').mockResolvedValue(mockStream);
    vi.spyOn(viewer, 'endStream').mockReturnValue(true);
    
    const handle = await mount.open(path);
    const result = mount.close(handle);
    
    expect(result).toBe(true);
    expect(mount.handles.size).toBe(0);
  });
  
  it('returns mount stats', async () => {
    await mount.mount();
    
    const stats = mount.getStats();
    expect(stats.mountPoint).toBe('/yak');
    expect(stats.mounted).toBe(true);
    expect(stats.virtualFiles).toBe(0);
    expect(stats.openHandles).toBe(0);
  });
});
