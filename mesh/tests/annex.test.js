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

      // Try to replay same message
      expect(() => bob.decrypt(encrypted, encrypted.sequence))
        .toThrow(/[Rr]eplay/);
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
