/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0. If a copy of that
 * license agreement was not distributed with this file, You can
 * find a link to the license at https://yakmesh.dev/license
 *
 * This Source Code Form is "Incompatible With Secondary Licenses",
 * as defined by the YAKMESH NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * ANNEX Channel Tests
 * 
 * Tests for ANNEX (Autonomous Network Negotiated Encrypted eXchange)
 * End-to-end encrypted point-to-point communication using ML-KEM768.
 * 
 * @version 2.3.0
 */

import { describe, test, expect, beforeEach, vi, afterEach } from 'vitest';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';

// Import ANNEX components
import Annex, {
  AnnexEnvelope,
  AnnexSession,
  ANNEX_CONFIG,
} from '../annex.js';

// ═══════════════════════════════════════════════════════════════════════════
// ANNEX ENVELOPE TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('AnnexEnvelope', () => {
  describe('Envelope Creation', () => {
    test('creates envelope with unique ID', () => {
      const envelope = new AnnexEnvelope({
        senderId: 'sender-node',
        recipientId: 'recipient-node',
        sessionId: 'session-123',
      });

      expect(envelope.id).toBeDefined();
      expect(envelope.id.length).toBe(32); // 16 bytes = 32 hex
    });

    test('two envelopes have different IDs', () => {
      const e1 = new AnnexEnvelope({ senderId: 'a', recipientId: 'b', sessionId: 's' });
      const e2 = new AnnexEnvelope({ senderId: 'a', recipientId: 'b', sessionId: 's' });

      expect(e1.id).not.toBe(e2.id);
    });

    test('sets default type to ENCRYPTED', () => {
      const envelope = new AnnexEnvelope({
        senderId: 'sender',
        recipientId: 'recipient',
        sessionId: 'session',
      });

      expect(envelope.type).toBe(ANNEX_CONFIG.messageTypes.ENCRYPTED);
    });

    test('accepts custom message type', () => {
      const keyExchange = new AnnexEnvelope({
        senderId: 'sender',
        recipientId: 'recipient',
        sessionId: 'session',
        type: ANNEX_CONFIG.messageTypes.KEY_EXCHANGE,
      });

      expect(keyExchange.type).toBe(ANNEX_CONFIG.messageTypes.KEY_EXCHANGE);
    });

    test('tracks sender and recipient', () => {
      const envelope = new AnnexEnvelope({
        senderId: 'alice',
        recipientId: 'bob',
        sessionId: 'chat-1',
      });

      expect(envelope.senderId).toBe('alice');
      expect(envelope.recipientId).toBe('bob');
    });

    test('initializes sequence to 0', () => {
      const envelope = new AnnexEnvelope({
        senderId: 'a',
        recipientId: 'b',
        sessionId: 's',
      });

      expect(envelope.sequence).toBe(0);
    });

    test('sets timestamp to creation time', () => {
      const before = Date.now();
      const envelope = new AnnexEnvelope({
        senderId: 'a',
        recipientId: 'b',
        sessionId: 's',
      });
      const after = Date.now();

      expect(envelope.timestamp).toBeGreaterThanOrEqual(before);
      expect(envelope.timestamp).toBeLessThanOrEqual(after);
    });
  });

  describe('Signing Payload', () => {
    test('getSigningPayload returns deterministic string', () => {
      const envelope = new AnnexEnvelope({
        id: 'fixed-id',
        senderId: 'alice',
        recipientId: 'bob',
        sessionId: 'session-1',
        sequence: 5,
        timestamp: 1234567890,
      });

      const payload1 = envelope.getSigningPayload();
      const payload2 = envelope.getSigningPayload();

      expect(payload1).toBe(payload2);
      expect(typeof payload1).toBe('string');
    });

    test('signing payload includes all envelope fields', () => {
      const envelope = new AnnexEnvelope({
        senderId: 'alice',
        recipientId: 'bob',
        sessionId: 'session-1',
        nonce: 'abc123',
        ciphertext: 'encrypted-data',
        authTag: 'tag123',
      });

      const payload = envelope.getSigningPayload();
      const parsed = JSON.parse(payload);

      expect(parsed.senderId).toBe('alice');
      expect(parsed.recipientId).toBe('bob');
      expect(parsed.nonce).toBe('abc123');
      expect(parsed.ciphertext).toBe('encrypted-data');
    });
  });

  describe('Serialization', () => {
    test('toJSON returns serializable object', () => {
      const envelope = new AnnexEnvelope({
        senderId: 'alice',
        recipientId: 'bob',
        sessionId: 'session-1',
        nonce: 'nonce-value',
        ciphertext: 'encrypted',
        authTag: 'tag',
        signature: 'sig',
      });

      const json = envelope.toJSON();

      expect(json.id).toBe(envelope.id);
      expect(json.senderId).toBe('alice');
      expect(json.recipientId).toBe('bob');
      expect(json.signature).toBe('sig');
    });

    test('fromJSON restores envelope', () => {
      const original = new AnnexEnvelope({
        senderId: 'alice',
        recipientId: 'bob',
        sessionId: 'session-1',
        sequence: 42,
        nonce: 'nonce',
        ciphertext: 'data',
        authTag: 'tag',
      });

      const json = original.toJSON();
      const restored = AnnexEnvelope.fromJSON(json);

      expect(restored.id).toBe(original.id);
      expect(restored.senderId).toBe(original.senderId);
      expect(restored.recipientId).toBe(original.recipientId);
      expect(restored.sequence).toBe(42);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// ANNEX SESSION TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('AnnexSession', () => {
  let session;

  beforeEach(() => {
    session = new AnnexSession({
      localNodeId: 'local-node',
      remoteNodeId: 'remote-node',
      initiator: true,
    });
  });

  describe('Session Creation', () => {
    test('creates session with unique ID', () => {
      expect(session.sessionId).toBeDefined();
      expect(session.sessionId.length).toBe(32);
    });

    test('tracks local and remote nodes', () => {
      expect(session.localNodeId).toBe('local-node');
      expect(session.remoteNodeId).toBe('remote-node');
    });

    test('tracks initiator status', () => {
      expect(session.initiator).toBe(true);

      const responder = new AnnexSession({
        localNodeId: 'responder',
        remoteNodeId: 'initiator',
        initiator: false,
      });
      expect(responder.initiator).toBe(false);
    });

    test('starts as not established', () => {
      expect(session.established).toBe(false);
    });

    test('initializes sequence counters', () => {
      expect(session.sendSequence).toBe(0);
      // recvSequence starts at -1 so the first message (seq 0) passes replay check
      expect(session.recvSequence).toBe(-1);
    });

    test('tracks creation time', () => {
      expect(session.createdAt).toBeDefined();
      expect(session.createdAt).toBeLessThanOrEqual(Date.now());
    });
  });

  describe('Key Generation (ML-KEM-768)', () => {
    test('generates ephemeral key pair', async () => {
      const publicKey = await session.generateKeyPair();

      expect(publicKey).toBeDefined();
      expect(typeof publicKey).toBe('string');
      expect(session.kemKeyPair).toBeDefined();
    });

    test('public key is valid hex string', async () => {
      const publicKey = await session.generateKeyPair();

      // ML-KEM-768 public key is 1184 bytes = 2368 hex chars
      expect(publicKey).toMatch(/^[0-9a-f]+$/i);
      expect(publicKey.length).toBe(2368);
    });
  });

  describe('Key Exchange', () => {
    let initiator, responder;

    beforeEach(async () => {
      initiator = new AnnexSession({
        localNodeId: 'alice',
        remoteNodeId: 'bob',
        initiator: true,
      });

      responder = new AnnexSession({
        sessionId: initiator.sessionId,
        localNodeId: 'bob',
        remoteNodeId: 'alice',
        initiator: false,
      });

      // Responder generates key pair first (async — uses PRAHARI seed)
      await responder.generateKeyPair();
    });

    test('initiator encapsulates with responder public key', () => {
      const responderPubKey = bytesToHex(responder.kemKeyPair.publicKey);
      const ciphertext = initiator.encapsulate(responderPubKey);

      expect(ciphertext).toBeDefined();
      expect(initiator.established).toBe(true);
      expect(initiator.sharedSecret).toBeDefined();
      expect(initiator.encryptionKey).toBeDefined();
    });

    test('responder decapsulates ciphertext', () => {
      const responderPubKey = bytesToHex(responder.kemKeyPair.publicKey);
      const ciphertext = initiator.encapsulate(responderPubKey);

      const success = responder.decapsulate(ciphertext);

      expect(success).toBe(true);
      expect(responder.established).toBe(true);
      expect(responder.sharedSecret).toBeDefined();
      expect(responder.encryptionKey).toBeDefined();
    });

    test('both parties derive same encryption key', () => {
      const responderPubKey = bytesToHex(responder.kemKeyPair.publicKey);
      const ciphertext = initiator.encapsulate(responderPubKey);
      responder.decapsulate(ciphertext);

      expect(bytesToHex(initiator.encryptionKey)).toBe(bytesToHex(responder.encryptionKey));
    });

    test('throws without key pair on decapsulation', () => {
      const freshSession = new AnnexSession({
        localNodeId: 'fresh',
        remoteNodeId: 'other',
      });

      expect(() => freshSession.decapsulate('abc123')).toThrow('No key pair generated');
    });

    test('records last rekey time', () => {
      const responderPubKey = bytesToHex(responder.kemKeyPair.publicKey);
      const before = Date.now();
      initiator.encapsulate(responderPubKey);
      const after = Date.now();

      expect(initiator.lastRekey).toBeGreaterThanOrEqual(before);
      expect(initiator.lastRekey).toBeLessThanOrEqual(after);
    });
  });

  describe('Message Encryption', () => {
    let alice, bob;

    beforeEach(async () => {
      alice = new AnnexSession({
        localNodeId: 'alice',
        remoteNodeId: 'bob',
        initiator: true,
      });

      bob = new AnnexSession({
        sessionId: alice.sessionId,
        localNodeId: 'bob',
        remoteNodeId: 'alice',
        initiator: false,
      });

      await bob.generateKeyPair();
      const bobPubKey = bytesToHex(bob.kemKeyPair.publicKey);
      const ciphertext = alice.encapsulate(bobPubKey);
      bob.decapsulate(ciphertext);
    });

    test('encrypts string message', () => {
      const encrypted = alice.encrypt('Hello, Bob!');

      expect(encrypted.nonce).toBeDefined();
      expect(encrypted.ciphertext).toBeDefined();
      expect(encrypted.authTag).toBeDefined();
      expect(encrypted.sequence).toBe(0);
    });

    test('encrypts object message', () => {
      const encrypted = alice.encrypt({ type: 'greeting', text: 'Hello!' });

      expect(encrypted.ciphertext).toBeDefined();
    });

    test('increments send sequence', () => {
      alice.encrypt('msg1');
      alice.encrypt('msg2');
      const encrypted = alice.encrypt('msg3');

      expect(alice.sendSequence).toBe(3);
      expect(encrypted.sequence).toBe(2);
    });

    test('updates last activity time', () => {
      const before = Date.now();
      alice.encrypt('message');
      const after = Date.now();

      expect(alice.lastActivity).toBeGreaterThanOrEqual(before);
      expect(alice.lastActivity).toBeLessThanOrEqual(after);
    });

    test('throws when session not established', () => {
      const unestablished = new AnnexSession({
        localNodeId: 'a',
        remoteNodeId: 'b',
      });

      expect(() => unestablished.encrypt('test')).toThrow('Session not established');
    });
  });

  describe('Message Decryption', () => {
    let alice, bob;

    beforeEach(async () => {
      alice = new AnnexSession({
        localNodeId: 'alice',
        remoteNodeId: 'bob',
        initiator: true,
      });

      bob = new AnnexSession({
        sessionId: alice.sessionId,
        localNodeId: 'bob',
        remoteNodeId: 'alice',
        initiator: false,
      });

      await bob.generateKeyPair();
      const bobPubKey = bytesToHex(bob.kemKeyPair.publicKey);
      const ciphertext = alice.encapsulate(bobPubKey);
      bob.decapsulate(ciphertext);
    });

    test('decrypts to original string', () => {
      const original = 'Secret message from Alice';
      const encrypted = alice.encrypt(original);
      const decrypted = bob.decrypt(encrypted, encrypted.sequence);

      expect(decrypted).toBe(original);
    });

    test('decrypts to original object', () => {
      const original = { action: 'transfer', amount: 1000 };
      const encrypted = alice.encrypt(original);
      const decrypted = JSON.parse(bob.decrypt(encrypted, encrypted.sequence));

      expect(decrypted).toEqual(original);
    });

    test('bidirectional communication works', () => {
      // Alice to Bob
      const msg1 = alice.encrypt('Hello Bob');
      const decrypted1 = bob.decrypt(msg1, msg1.sequence);
      expect(decrypted1).toBe('Hello Bob');

      // Bob to Alice
      const msg2 = bob.encrypt('Hello Alice');
      const decrypted2 = alice.decrypt(msg2, msg2.sequence);
      expect(decrypted2).toBe('Hello Alice');
    });

    test('throws when session not established', () => {
      const unestablished = new AnnexSession({
        localNodeId: 'a',
        remoteNodeId: 'b',
      });

      expect(() => unestablished.decrypt({ nonce: 'a', ciphertext: 'b', authTag: 'c' }, 0))
        .toThrow('Session not established');
    });

    test('detects replay attack (reused sequence)', () => {
      const encrypted = alice.encrypt('message');
      bob.decrypt(encrypted, encrypted.sequence);

      // Try to replay same message — a true duplicate, rejected
      expect(() => bob.decrypt(encrypted, encrypted.sequence))
        .toThrow(/[Dd]uplicate/);
    });

    test('accepts in-window late arrivals (dual-wire reorder)', () => {
      // Dual-wire shares one forward send counter across sockets of
      // different latency — whichever wire is faster wins; the slower
      // wire's earlier sequences legitimately arrive late and must NOT
      // be rejected as replays.
      const m0 = alice.encrypt('first');
      const m1 = alice.encrypt('second');
      const m2 = alice.encrypt('third');

      // Wire B delivers seq 2 first, then wire A's earlier seqs arrive
      bob.decrypt(m2, m2.sequence);
      expect(() => bob.decrypt(m0, m0.sequence)).not.toThrow();
      expect(() => bob.decrypt(m1, m1.sequence)).not.toThrow();

      // ...but a second copy of an already-seen seq is a true duplicate
      expect(() => bob.decrypt(m0, m0.sequence)).toThrow(/[Dd]uplicate/);
    });

    test('tampered ciphertext fails authentication', () => {
      const encrypted = alice.encrypt('sensitive data');
      encrypted.ciphertext = 'ff' + encrypted.ciphertext.slice(2);

      expect(() => bob.decrypt(encrypted, encrypted.sequence)).toThrow();
    });

    test('wrong auth tag fails', () => {
      const encrypted = alice.encrypt('data');
      encrypted.authTag = bytesToHex(randomBytes(16));

      expect(() => bob.decrypt(encrypted, encrypted.sequence)).toThrow();
    });
  });

  describe('Session Lifecycle', () => {
    test('tracks message count', async () => {
      const alice = new AnnexSession({ localNodeId: 'a', remoteNodeId: 'b' });
      const bob = new AnnexSession({ localNodeId: 'b', remoteNodeId: 'a' });

      await bob.generateKeyPair();
      alice.encapsulate(bytesToHex(bob.kemKeyPair.publicKey));

      alice.encrypt('1');
      alice.encrypt('2');
      alice.encrypt('3');

      expect(alice.messageCount).toBe(3);
    });

    // needsRekey tests REMOVED — JHILKE v2 replaced KEM-based rekeying
    // with deterministic bootstrap keys. No rekeyInterval or maxMessagesPerKey.

    test('isExpired returns false for active session', async () => {
      const alice = new AnnexSession({ localNodeId: 'a', remoteNodeId: 'b' });
      const bob = new AnnexSession({ localNodeId: 'b', remoteNodeId: 'a' });

      await bob.generateKeyPair();
      alice.encapsulate(bytesToHex(bob.kemKeyPair.publicKey));

      expect(alice.isExpired()).toBe(false);
    });

    test('isExpired returns true after timeout', async () => {
      const alice = new AnnexSession({ localNodeId: 'a', remoteNodeId: 'b' });
      const bob = new AnnexSession({ localNodeId: 'b', remoteNodeId: 'a' });

      await bob.generateKeyPair();
      alice.encapsulate(bytesToHex(bob.kemKeyPair.publicKey));

      // Simulate old session — isExpired() checks lastActivity, not createdAt
      alice.lastActivity = Date.now() - ANNEX_CONFIG.sessionTimeout - 1000;

      expect(alice.isExpired()).toBe(true);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// ANNEX CLASS TESTS (formerly AnnexChannel)
// ═══════════════════════════════════════════════════════════════════════════

describe('Annex', () => {
  let annex;
  let mockIdentity;

  beforeEach(() => {
    mockIdentity = {
      identity: {
        nodeId: 'channel-test-node',
      },
      sign: vi.fn((data) => 'mock-signature'),
      verify: vi.fn(() => true),
    };

    annex = new Annex({
      identity: mockIdentity,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Annex Initialization', () => {
    test('creates annex with identity', () => {
      expect(annex.identity).toBe(mockIdentity);
    });

    test('initializes empty session map', () => {
      expect(annex.sessions.size).toBe(0);
    });

    test('initializes stats', () => {
      expect(annex.stats).toBeDefined();
      expect(annex.stats.messagesEncrypted).toBe(0);
      expect(annex.stats.messagesDecrypted).toBe(0);
      expect(annex.stats.sessionsCreated).toBe(0);
    });
  });

  describe('Session Management', () => {
    // openChannel, increments sessionsCreated — require live mesh connection,
    // covered by integration/e2e tests rather than unit tests.

    test('sessions.get retrieves existing session', () => {
      // Manually add a session for testing
      const session = new AnnexSession({
        localNodeId: 'channel-test-node',
        remoteNodeId: 'remote-peer',
        initiator: true,
      });
      annex.sessions.set('remote-peer', session);

      const retrieved = annex.sessions.get('remote-peer');
      expect(retrieved).toBe(session);
    });

    test('sessions.get returns undefined for unknown peer', () => {
      const session = annex.sessions.get('unknown-peer');
      expect(session).toBeUndefined();
    });

    test('sessions.delete removes session', () => {
      const session = new AnnexSession({
        localNodeId: 'channel-test-node',
        remoteNodeId: 'remote-peer',
        initiator: true,
      });
      annex.sessions.set('remote-peer', session);
      annex.sessions.delete('remote-peer');

      expect(annex.sessions.size).toBe(0);
    });

    // sessionsCreated stat — requires live mesh connection
  });

  // Key Exchange Messages — internal to Annex, tested via E2E integration

  describe('Encrypted Messaging', () => {
    let peerAnnex;

    beforeEach(async () => {
      const peerIdentity = {
        identity: {
          nodeId: 'peer-node',
        },
        sign: vi.fn(() => 'peer-signature'),
        verify: vi.fn(() => true),
      };

      peerAnnex = new Annex({
        identity: peerIdentity,
      });

      // Establish session manually for testing
      const localSession = new AnnexSession({
        localNodeId: 'channel-test-node',
        remoteNodeId: 'peer-node',
        initiator: true,
      });

      const peerSession = new AnnexSession({
        sessionId: localSession.sessionId,
        localNodeId: 'peer-node',
        remoteNodeId: 'channel-test-node',
        initiator: false,
      });

      await peerSession.generateKeyPair();
      const ciphertext = localSession.encapsulate(bytesToHex(peerSession.kemKeyPair.publicKey));
      peerSession.decapsulate(ciphertext);

      annex.sessions.set('peer-node', localSession);
      peerAnnex.sessions.set('channel-test-node', peerSession);
    });

    // send/sign/stats — require live mesh connection,
    // covered by integration/e2e tests rather than unit tests.

    test('established session can encrypt and decrypt between peers', () => {
      const localSession = annex.sessions.get('peer-node');
      const peerSession = peerAnnex.sessions.get('channel-test-node');

      const encrypted = localSession.encrypt('test message');
      const decrypted = peerSession.decrypt(encrypted, encrypted.sequence);
      expect(decrypted).toBe('test message');
    });
  });

  describe('Session Cleanup', () => {
    test('getSessionInfo returns null for unknown session', () => {
      const info = annex.getSessionInfo('unknown-peer');
      expect(info).toBeNull();
    });

    test('getSessionInfo returns info for known session', async () => {
      const localSession = new AnnexSession({
        localNodeId: 'channel-test-node',
        remoteNodeId: 'info-peer',
        initiator: true,
      });
      const peerSession = new AnnexSession({
        sessionId: localSession.sessionId,
        localNodeId: 'info-peer',
        remoteNodeId: 'channel-test-node',
        initiator: false,
      });
      await peerSession.generateKeyPair();
      localSession.encapsulate(bytesToHex(peerSession.kemKeyPair.publicKey));

      annex.sessions.set('info-peer', localSession);
      const info = annex.getSessionInfo('info-peer');

      expect(info).toBeDefined();
      expect(info.sessionId).toBe(localSession.sessionId);
      expect(info.established).toBe(true);
    });

    test('listAnnexes returns all sessions', () => {
      const session1 = new AnnexSession({
        localNodeId: 'channel-test-node',
        remoteNodeId: 'peer-1',
      });
      const session2 = new AnnexSession({
        localNodeId: 'channel-test-node',
        remoteNodeId: 'peer-2',
      });

      annex.sessions.set('peer-1', session1);
      annex.sessions.set('peer-2', session2);

      const annexes = annex.listAnnexes();
      expect(annexes.length).toBe(2);
    });

    test('getStats returns current stats', () => {
      const stats = annex.getStats();
      expect(stats).toBeDefined();
      expect(stats.activeSessions).toBe(0);
      expect(stats.sessionsCreated).toBe(0);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('ANNEX Configuration', () => {
  test('uses AES-256-GCM for symmetric encryption', () => {
    expect(ANNEX_CONFIG.symmetricAlgorithm).toBe('aes-256-gcm');
  });

  test('has proper nonce and tag sizes', () => {
    expect(ANNEX_CONFIG.nonceSize).toBe(12);
    expect(ANNEX_CONFIG.authTagLength).toBe(16);
  });

  test('has session timeout configured', () => {
    expect(ANNEX_CONFIG.sessionTimeout).toBeGreaterThan(0);
  });

  test('has all required message types', () => {
    expect(ANNEX_CONFIG.messageTypes.KEY_EXCHANGE).toBeDefined();
    expect(ANNEX_CONFIG.messageTypes.KEY_RESPONSE).toBeDefined();
    expect(ANNEX_CONFIG.messageTypes.ENCRYPTED).toBeDefined();
    expect(ANNEX_CONFIG.messageTypes.CLOSE).toBeDefined();
    // REKEY type removed — JHILKE v2 handles all rekeys deterministically
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('ANNEX End-to-End Integration', () => {
  test('full key exchange and messaging flow', async () => {
    // Create two identities
    const aliceIdentity = {
      nodeId: 'alice',
      sign: (data) => 'alice-sig',
      verify: () => true,
    };

    const bobIdentity = {
      nodeId: 'bob',
      sign: (data) => 'bob-sig',
      verify: () => true,
    };

    // Create sessions directly for integration test
    const aliceSession = new AnnexSession({
      localNodeId: 'alice',
      remoteNodeId: 'bob',
      initiator: true,
    });

    const bobSession = new AnnexSession({
      sessionId: aliceSession.sessionId,
      localNodeId: 'bob',
      remoteNodeId: 'alice',
      initiator: false,
    });

    // Bob generates key pair
    const bobPubKey = await bobSession.generateKeyPair();

    // Alice encapsulates (key exchange initiation)
    const ciphertext = aliceSession.encapsulate(bobPubKey);

    // Bob decapsulates (key exchange completion)
    bobSession.decapsulate(ciphertext);

    // Verify both have same key
    expect(bytesToHex(aliceSession.encryptionKey)).toBe(bytesToHex(bobSession.encryptionKey));

    // Alice sends encrypted message to Bob
    const encrypted = aliceSession.encrypt('Hello Bob!');
    const decrypted = bobSession.decrypt(encrypted, encrypted.sequence);

    expect(decrypted).toBe('Hello Bob!');

    // Bob responds
    const response = bobSession.encrypt('Hello Alice!');
    const decryptedResponse = aliceSession.decrypt(response, response.sequence);

    expect(decryptedResponse).toBe('Hello Alice!');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SECURITY: ANNEX Signature Verification (CRITICAL 5.1 regression test)
// ═══════════════════════════════════════════════════════════════════════════

describe('ANNEX Signature Enforcement (CRITICAL 5.1)', () => {
  let annex;
  let mockIdentity;
  let messageProcessed;

  beforeEach(() => {
    messageProcessed = false;
    mockIdentity = {
      identity: { nodeId: 'local-node' },
      sign: vi.fn(() => 'mock-signature'),
      verify: vi.fn(() => true),
    };

    const mockMesh = {
      on: vi.fn(),
      peers: new Map(),
      _relayPeerKeys: new Map(),
    };

    annex = new Annex({ identity: mockIdentity, mesh: mockMesh });
  });

  test('rejects ANNEX message when sender pubkey is unknown', async () => {
    // Forge an envelope from a completely unknown nodeId
    const forgedEnvelope = {
      id: 'forged-1',
      type: ANNEX_CONFIG.messageTypes.KEY_EXCHANGE,
      senderId: 'attacker-node-unknown',
      recipientId: 'local-node',
      sessionId: 'fake-session',
      sequence: 0,
      timestamp: Date.now(),
      kemPublicKey: 'deadbeef',
      signature: 'forged-sig',
    };

    // _handleAnnexMessage should return without processing
    await annex._handleAnnexMessage(forgedEnvelope, null);

    // identity.verify should NEVER have been called (no key to verify against)
    expect(mockIdentity.verify).not.toHaveBeenCalled();
    // No session should have been created
    expect(annex.sessions.size).toBe(0);
    expect(annex.stats.sessionsCreated).toBe(0);
  });

  test('rejects ANNEX message with invalid signature from known peer', async () => {
    // Register a known peer
    annex.mesh.peers.set('known-peer', {
      identity: { publicKey: 'known-peer-pubkey-hex' },
    });

    // verify returns FALSE for this peer
    mockIdentity.verify.mockReturnValue(false);

    const envelope = {
      id: 'bad-sig-1',
      type: ANNEX_CONFIG.messageTypes.ENCRYPTED,
      senderId: 'known-peer',
      recipientId: 'local-node',
      sessionId: 'some-session',
      sequence: 5,
      timestamp: Date.now(),
      nonce: 'abc',
      ciphertext: 'def',
      authTag: 'ghi',
      signature: 'invalid-signature',
    };

    await annex._handleAnnexMessage(envelope, null);

    // verify WAS called with the known key
    expect(mockIdentity.verify).toHaveBeenCalledTimes(1);
    // But no session or decryption happened
    expect(annex.sessions.size).toBe(0);
  });

  test('processes ANNEX message with valid signature from known peer', async () => {
    // Register a known peer
    annex.mesh.peers.set('known-peer', {
      identity: { publicKey: 'known-peer-pubkey-hex' },
    });

    // verify returns TRUE
    mockIdentity.verify.mockReturnValue(true);

    const envelope = {
      id: 'valid-1',
      type: ANNEX_CONFIG.messageTypes.KEY_EXCHANGE,
      senderId: 'known-peer',
      recipientId: 'local-node',
      sessionId: 'session-1',
      sequence: 0,
      timestamp: Date.now(),
      kemPublicKey: bytesToHex(new Uint8Array(1184)), // ML-KEM-768 pub key size
      signature: 'valid-sig',
    };

    // This will try to complete the key exchange (may throw because the
    // KEM public key is zeroed), but the point is verify() was called and
    // passed — the message was NOT rejected at the gate.
    try {
      await annex._handleAnnexMessage(envelope, null);
    } catch { /* KEM processing may fail; that's OK */ }

    // verify was called (gate opened)
    expect(mockIdentity.verify).toHaveBeenCalledTimes(1);
  });

  test('unknown peer cannot forge KEY_EXCHANGE to create session', async () => {
    // This is the core of CRITICAL 5.1: an attacker with a fabricated senderId
    // should NEVER get past signature verification.
    const envelope = {
      id: 'forge-ke',
      type: ANNEX_CONFIG.messageTypes.KEY_EXCHANGE,
      senderId: 'nonexistent-attacker-id',
      recipientId: 'local-node',
      sessionId: 'forged-session',
      sequence: 0,
      timestamp: Date.now(),
      kemPublicKey: 'aabbccdd',
      signature: 'attacker-sig',
    };

    await annex._handleAnnexMessage(envelope, null);

    // No session created, no handshake stored
    expect(annex.sessions.size).toBe(0);
    expect(annex.pendingHandshakes.size).toBe(0);
  });
});


// ═══════════════════════════════════════════════════════════════════════════
// EPOCH-BOUND WIRE KEYS (AVOTH phase flip)
// Wire key = derivePhaseModulated(sessionBase, epoch). Both peers share the
// AGUWA epoch clock, so keys rotate every phase with zero round-trips; the
// receiver accepts epoch ±1 to absorb boundary straddle.
// ═══════════════════════════════════════════════════════════════════════════

// Wire epochs are driven by AnnexSession._wireEpoch() — a fixed 6h cadence
// on AGUWA time (deliberately NOT getCurrentEpoch's trust-scaled value).
// Tests override _wireEpoch per session to simulate boundary straddle.
const epochCtl = { epoch: null };
import { aguwa } from '../../mesh/aguwa.js';

describe('AnnexSession — epoch-bound wire keys', () => {
  let alice, bob;
  let baseEpoch;

  beforeEach(async () => {
    alice = new AnnexSession({
      localNodeId: 'alice',
      remoteNodeId: 'bob',
      initiator: true,
    });
    bob = new AnnexSession({
      sessionId: alice.sessionId,
      localNodeId: 'bob',
      remoteNodeId: 'alice',
      initiator: false,
    });
    await bob.generateKeyPair();
    const ct = alice.encapsulate(bytesToHex(bob.kemKeyPair.publicKey));
    bob.decapsulate(ct);
    baseEpoch = Math.floor(aguwa.now() / (6 * 60 * 60 * 1000));
    epochCtl.epoch = baseEpoch;
    const wireEpoch = () => epochCtl.epoch;
    alice._wireEpoch = wireEpoch;
    bob._wireEpoch = wireEpoch;
  });

  afterEach(() => { epochCtl.epoch = null; });

  test('same-epoch round trip', () => {
    const msg = alice.encrypt('phase-locked');
    expect(bob.decrypt(msg, msg.sequence)).toBe('phase-locked');
  });

  test('wire key differs across epochs for same base', () => {
    const k0 = alice._epochKeyFor(alice.encryptionKey, baseEpoch);
    const k1 = alice._epochKeyFor(alice.encryptionKey, baseEpoch + 1);
    expect(Buffer.compare(k0, k1)).not.toBe(0);
  });

  test('receiver decrypts previous-epoch ciphertext (sender behind)', () => {
    const msg = alice.encrypt('sent before flip');
    epochCtl.epoch = baseEpoch + 1; // receiver now one epoch ahead
    expect(bob.decrypt(msg, msg.sequence)).toBe('sent before flip');
  });

  test('receiver decrypts next-epoch ciphertext (sender ahead)', () => {
    epochCtl.epoch = baseEpoch + 1;
    const msg = alice.encrypt('sent after flip');
    epochCtl.epoch = baseEpoch; // receiver still on old epoch
    expect(bob.decrypt(msg, msg.sequence)).toBe('sent after flip');
  });

  test('post-flip traffic uses the new epoch key both ways', () => {
    epochCtl.epoch = baseEpoch + 1;
    const msg = alice.encrypt('new epoch');
    expect(bob.decrypt(msg, msg.sequence)).toBe('new epoch');
  });

  test('rejects ciphertext from epoch ±2 (outside window)', () => {
    const msg = alice.encrypt('too old');
    epochCtl.epoch = baseEpoch + 2;
    expect(() => bob.decrypt(msg, msg.sequence)).toThrow();
  });

  test('replay protection survives an epoch flip', () => {
    const m1 = alice.encrypt('one');
    const m2 = alice.encrypt('two');
    epochCtl.epoch = baseEpoch + 1;
    bob.decrypt(m2, m2.sequence); // forward seq accepted post-flip
    bob.decrypt(m1, m1.sequence); // delayed slower-wire seq inside window
    expect(() => bob.decrypt(m2, m2.sequence)).toThrow(/Duplicate/);
  });

  test('wire epoch is canonical — immune to trust-scaled epochDurationHours', async () => {
    // Regression: getCurrentEpoch() follows setTimeSourceConfig trust levels
    // (1/2/6/12h) — two healthy nodes once derived different epochs and could
    // never decrypt each other. _wireEpoch must stay on the fixed 6h cadence.
    const fresh = new AnnexSession({ localNodeId: 'x', remoteNodeId: 'y' });
    const { setPhaseConfig, getCurrentEpoch } = await import('../../oracle/phase-epoch.js');
    const before = fresh._wireEpoch();
    setPhaseConfig('gps');   // 2h epochs — would change getCurrentEpoch
    setPhaseConfig('unsync'); // 12h epochs
    expect(fresh._wireEpoch()).toBe(before);
    // restore default for other tests
    setPhaseConfig('ntp');
  });

  test('send-key cache invalidates on epoch flip and base change', () => {
    const k0 = alice._sendKey();
    epochCtl.epoch = baseEpoch + 1;
    const k1 = alice._sendKey();
    expect(Buffer.compare(k0, k1)).not.toBe(0);
    // Base change (e.g. KEM upgrade) invalidates even at same epoch
    const before = alice._sendKey();
    alice.encryptionKey = randomBytes(32);
    alice._sendKeyEpoch = -1; // mirrors assignment-site invalidation
    expect(Buffer.compare(before, alice._sendKey())).not.toBe(0);
  });
});


describe('AnnexSession — handshake race hardening', () => {
  let annex;
  let sendCalls;

  beforeEach(() => {
    const mockIdentity = {
      identity: { nodeId: 'node-b', publicKey: 'aa'.repeat(32) },
      sign: vi.fn(() => 'mock-signature'),
      verify: vi.fn(() => true),
    };
    sendCalls = [];
    const mockMesh = {
      on: vi.fn(),
      peers: new Map(),
      _relayPeerKeys: new Map(),
      sendTo: vi.fn((id, env) => { sendCalls.push(env); return true; }),
    };
    annex = new Annex({ identity: mockIdentity, mesh: mockMesh });
  });

  test('concurrent openChannel calls share one pending handshake', async () => {
    // First call fires the KEX; the second must reuse it — a stomp would
    // overwrite pendingHandshakes and orphan the first session.
    const p1 = annex.openChannel('node-a');
    const p2 = annex.openChannel('node-a');
    expect(annex.pendingHandshakes.size).toBe(1); // synchronous dedup
    await vi.waitFor(() => expect(sendCalls.length).toBeGreaterThan(0));
    const kexCount = sendCalls.filter(e => e.annex?.type === ANNEX_CONFIG.messageTypes.KEY_EXCHANGE).length;
    expect(kexCount).toBe(1);
    // Settle both to avoid dangling timers
    const s = annex.pendingHandshakes.get('node-a');
    s._resolveHandshake(s);
    await Promise.all([p1, p2]);
  });

  test('stale KEY_RESPONSE (wrong sessionId) is ignored, not decapsulated', async () => {
    const p = annex.openChannel('node-a');
    const pending = annex.pendingHandshakes.get('node-a'); // set synchronously
    expect(pending).toBeDefined();
    const decapSpy = vi.spyOn(pending, 'decapsulate');
    await annex._handleKeyResponse({
      senderId: 'node-a',
      sessionId: 'superseded-session-id',
      kemCiphertext: 'aa',
    });
    expect(decapSpy).not.toHaveBeenCalled();
    expect(annex.pendingHandshakes.has('node-a')).toBe(true);
    pending._resolveHandshake(pending);
    await p;
  });

  test('session establishment resets the auth-failure counter', async () => {
    annex._authFailCount = new Map([['node-a', 5]]);
    annex.bootstrapSession('node-a', randomBytes(32));
    expect(annex._authFailCount.get('node-a')).toBeUndefined();
  });
});
