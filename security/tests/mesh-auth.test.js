/**
 * Mesh Auth Tests
 * 
 * Tests for MeshAuthenticator - WebSocket authentication and message encryption
 * for private networks.
 * 
 * @version 2.3.0
 */

import { describe, test, expect, beforeEach, vi, afterEach } from 'vitest';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';

// Import MeshAuthenticator
import { MeshAuthenticator } from '../mesh-auth.js';

// ═══════════════════════════════════════════════════════════════════════════
// MOCK SETUP
// ═══════════════════════════════════════════════════════════════════════════

function createMockIdentity(nodeId = 'test-node') {
  return {
    identity: {
      nodeId,
      publicKey: bytesToHex(randomBytes(32)),
    },
    sign: vi.fn((data) => bytesToHex(randomBytes(64))),
    verify: vi.fn(() => true),
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// MESH AUTHENTICATOR INITIALIZATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('MeshAuthenticator Initialization', () => {
  let authenticator;
  let mockIdentity;

  beforeEach(() => {
    mockIdentity = createMockIdentity();
    authenticator = new MeshAuthenticator(mockIdentity);
  });

  test('creates authenticator with identity', () => {
    expect(authenticator.identity).toBe(mockIdentity);
  });

  test('defaults requireAuth to false', () => {
    expect(authenticator.options.requireAuth).toBe(false);
  });

  test('accepts requireAuth option', () => {
    const strictAuth = new MeshAuthenticator(mockIdentity, { requireAuth: true });
    expect(strictAuth.options.requireAuth).toBe(true);
  });

  test('initializes empty allowlist', () => {
    expect(authenticator.options.allowlist.size).toBe(0);
  });

  test('initializes empty blocklist', () => {
    expect(authenticator.options.blocklist.size).toBe(0);
  });

  test('accepts initial allowlist', () => {
    const withAllowlist = new MeshAuthenticator(mockIdentity, {
      allowlist: ['peer-1', 'peer-2'],
    });
    expect(withAllowlist.options.allowlist.has('peer-1')).toBe(true);
    expect(withAllowlist.options.allowlist.has('peer-2')).toBe(true);
  });

  test('accepts initial blocklist', () => {
    const withBlocklist = new MeshAuthenticator(mockIdentity, {
      blocklist: ['bad-peer'],
    });
    expect(withBlocklist.options.blocklist.has('bad-peer')).toBe(true);
  });

  test('initializes empty pending challenges', () => {
    expect(authenticator.pendingChallenges.size).toBe(0);
  });

  test('initializes empty sessions', () => {
    expect(authenticator.sessions.size).toBe(0);
  });

  test('initializes stats to zero', () => {
    expect(authenticator.stats.authAttempts).toBe(0);
    expect(authenticator.stats.authSuccess).toBe(0);
    expect(authenticator.stats.authFailed).toBe(0);
    expect(authenticator.stats.blocked).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// ALLOWLIST/BLOCKLIST TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('MeshAuthenticator isAllowed', () => {
  let authenticator;
  let mockIdentity;

  beforeEach(() => {
    mockIdentity = createMockIdentity();
  });

  test('allows all peers when no allowlist set', () => {
    authenticator = new MeshAuthenticator(mockIdentity);
    expect(authenticator.isAllowed('any-peer')).toBe(true);
  });

  test('only allows peers in allowlist when set', () => {
    authenticator = new MeshAuthenticator(mockIdentity, {
      allowlist: ['allowed-peer'],
    });

    expect(authenticator.isAllowed('allowed-peer')).toBe(true);
    expect(authenticator.isAllowed('other-peer')).toBe(false);
  });

  test('blocks peers in blocklist', () => {
    authenticator = new MeshAuthenticator(mockIdentity, {
      blocklist: ['blocked-peer'],
    });

    expect(authenticator.isAllowed('blocked-peer')).toBe(false);
    expect(authenticator.isAllowed('other-peer')).toBe(true);
  });

  test('blocklist takes priority over allowlist', () => {
    authenticator = new MeshAuthenticator(mockIdentity, {
      allowlist: ['peer-1'],
      blocklist: ['peer-1'],
    });

    expect(authenticator.isAllowed('peer-1')).toBe(false);
  });

  test('increments blocked stat when peer is blocked', () => {
    authenticator = new MeshAuthenticator(mockIdentity, {
      blocklist: ['blocked-peer'],
    });

    authenticator.isAllowed('blocked-peer');
    authenticator.isAllowed('blocked-peer');

    expect(authenticator.stats.blocked).toBe(2);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// CHALLENGE GENERATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('MeshAuthenticator generateChallenge', () => {
  let authenticator;
  let mockIdentity;

  beforeEach(() => {
    mockIdentity = createMockIdentity('challenger-node');
    authenticator = new MeshAuthenticator(mockIdentity);
  });

  test('generates challenge with type', () => {
    const challenge = authenticator.generateChallenge('peer-1');
    expect(challenge.type).toBe('auth_challenge');
  });

  test('generates unique challenge ID', () => {
    const c1 = authenticator.generateChallenge('peer-1');
    const c2 = authenticator.generateChallenge('peer-2');

    expect(c1.challengeId).not.toBe(c2.challengeId);
    expect(c1.challengeId.length).toBe(32);
  });

  test('generates unique nonce', () => {
    const c1 = authenticator.generateChallenge('peer-1');
    const c2 = authenticator.generateChallenge('peer-2');

    expect(c1.nonce).not.toBe(c2.nonce);
    expect(c1.nonce.length).toBe(64);
  });

  test('includes timestamp', () => {
    const before = Date.now();
    const challenge = authenticator.generateChallenge('peer-1');
    const after = Date.now();

    expect(challenge.timestamp).toBeGreaterThanOrEqual(before);
    expect(challenge.timestamp).toBeLessThanOrEqual(after);
  });

  test('includes challenger node ID', () => {
    const challenge = authenticator.generateChallenge('peer-1');
    expect(challenge.challengerNodeId).toBe('challenger-node');
  });

  test('stores challenge in pending map', () => {
    const challenge = authenticator.generateChallenge('peer-1');

    expect(authenticator.pendingChallenges.has(challenge.challengeId)).toBe(true);
    const pending = authenticator.pendingChallenges.get(challenge.challengeId);
    expect(pending.peerId).toBe('peer-1');
  });

  test('increments authAttempts stat', () => {
    authenticator.generateChallenge('peer-1');
    authenticator.generateChallenge('peer-2');

    expect(authenticator.stats.authAttempts).toBe(2);
  });

  test('throws when max pending challenges reached', () => {
    const limited = new MeshAuthenticator(mockIdentity, {
      maxPendingAuth: 2,
    });

    limited.generateChallenge('peer-1');
    limited.generateChallenge('peer-2');

    expect(() => limited.generateChallenge('peer-3'))
      .toThrow(/[Tt]oo many pending/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// CHALLENGE RESPONSE TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('MeshAuthenticator respondToChallenge', () => {
  let authenticator;
  let mockIdentity;

  beforeEach(() => {
    mockIdentity = createMockIdentity('responder-node');
    authenticator = new MeshAuthenticator(mockIdentity);
  });

  test('creates response with correct type', () => {
    const challenge = {
      type: 'auth_challenge',
      challengeId: bytesToHex(randomBytes(16)),
      nonce: bytesToHex(randomBytes(32)),
      timestamp: Date.now(),
      challengerNodeId: 'challenger-node',
    };

    const response = authenticator.respondToChallenge(challenge);

    expect(response.type).toBe('auth_response');
  });

  test('includes challenge ID in response', () => {
    const challengeId = bytesToHex(randomBytes(16));
    const challenge = {
      type: 'auth_challenge',
      challengeId,
      nonce: bytesToHex(randomBytes(32)),
      timestamp: Date.now(),
      challengerNodeId: 'challenger',
    };

    const response = authenticator.respondToChallenge(challenge);

    expect(response.challengeId).toBe(challengeId);
  });

  test('includes responder node ID', () => {
    const challenge = {
      type: 'auth_challenge',
      challengeId: bytesToHex(randomBytes(16)),
      nonce: bytesToHex(randomBytes(32)),
      timestamp: Date.now(),
      challengerNodeId: 'challenger',
    };

    const response = authenticator.respondToChallenge(challenge);

    expect(response.responderNodeId).toBe('responder-node');
  });

  test('includes responder public key', () => {
    const challenge = {
      type: 'auth_challenge',
      challengeId: bytesToHex(randomBytes(16)),
      nonce: bytesToHex(randomBytes(32)),
      timestamp: Date.now(),
      challengerNodeId: 'challenger',
    };

    const response = authenticator.respondToChallenge(challenge);

    expect(response.responderPublicKey).toBe(mockIdentity.identity.publicKey);
  });

  test('signs the response', () => {
    const challenge = {
      type: 'auth_challenge',
      challengeId: bytesToHex(randomBytes(16)),
      nonce: bytesToHex(randomBytes(32)),
      timestamp: Date.now(),
      challengerNodeId: 'challenger',
    };

    const response = authenticator.respondToChallenge(challenge);

    expect(mockIdentity.sign).toHaveBeenCalled();
    expect(response.signature).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// VERIFY RESPONSE TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('MeshAuthenticator verifyResponse', () => {
  let challenger, responder;
  let challengerIdentity, responderIdentity;

  beforeEach(() => {
    challengerIdentity = createMockIdentity('challenger-node');
    responderIdentity = createMockIdentity('responder-node');

    challenger = new MeshAuthenticator(challengerIdentity);
    responder = new MeshAuthenticator(responderIdentity);
  });

  test('verifies valid response', () => {
    const challenge = challenger.generateChallenge('responder-node');
    const response = responder.respondToChallenge(challenge);

    const result = challenger.verifyResponse(response);

    expect(result.valid).toBe(true);
    expect(result.peerId).toBe('responder-node');
  });

  test('returns session key on success', () => {
    const challenge = challenger.generateChallenge('responder-node');
    const response = responder.respondToChallenge(challenge);

    const result = challenger.verifyResponse(response);

    expect(result.sessionKey).toBeDefined();
    expect(result.sessionKey.length).toBe(64); // 32 bytes = 64 hex
  });

  test('creates session on success', () => {
    const challenge = challenger.generateChallenge('responder-node');
    const response = responder.respondToChallenge(challenge);

    challenger.verifyResponse(response);

    expect(challenger.sessions.has('responder-node')).toBe(true);
  });

  test('emits authenticated event', () => {
    const handler = vi.fn();
    challenger.on('authenticated', handler);

    const challenge = challenger.generateChallenge('responder-node');
    const response = responder.respondToChallenge(challenge);
    challenger.verifyResponse(response);

    expect(handler).toHaveBeenCalledWith({ peerId: 'responder-node' });
  });

  test('increments authSuccess stat', () => {
    const challenge = challenger.generateChallenge('responder-node');
    const response = responder.respondToChallenge(challenge);
    challenger.verifyResponse(response);

    expect(challenger.stats.authSuccess).toBe(1);
  });

  test('removes pending challenge after verification', () => {
    const challenge = challenger.generateChallenge('responder-node');
    const response = responder.respondToChallenge(challenge);
    challenger.verifyResponse(response);

    expect(challenger.pendingChallenges.has(challenge.challengeId)).toBe(false);
  });

  test('rejects unknown challenge ID', () => {
    const response = {
      type: 'auth_response',
      challengeId: 'unknown-challenge',
      responderNodeId: 'responder-node',
      responderPublicKey: bytesToHex(randomBytes(32)),
      responseData: '{}',
      signature: bytesToHex(randomBytes(64)),
    };

    const result = challenger.verifyResponse(response);

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/[Uu]nknown.*challenge|expired/);
  });

  test('rejects invalid signature', () => {
    challengerIdentity.verify.mockReturnValue(false);

    const challenge = challenger.generateChallenge('responder-node');
    const response = responder.respondToChallenge(challenge);

    const result = challenger.verifyResponse(response);

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/[Ii]nvalid.*signature/);
  });

  test('increments authFailed on invalid signature', () => {
    challengerIdentity.verify.mockReturnValue(false);

    const challenge = challenger.generateChallenge('responder-node');
    const response = responder.respondToChallenge(challenge);
    challenger.verifyResponse(response);

    expect(challenger.stats.authFailed).toBe(1);
  });

  test('rejects blocked peer', () => {
    challenger.block('responder-node');

    const challenge = challenger.generateChallenge('responder-node');
    const response = responder.respondToChallenge(challenge);

    const result = challenger.verifyResponse(response);

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/[Nn]ot allowed/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SESSION MANAGEMENT TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('MeshAuthenticator Session Management', () => {
  let authenticator;
  let mockIdentity;

  beforeEach(() => {
    mockIdentity = createMockIdentity();
    authenticator = new MeshAuthenticator(mockIdentity);

    // Create a session manually
    authenticator.sessions.set('peer-1', {
      publicKey: bytesToHex(randomBytes(32)),
      sessionKey: randomBytes(32),
      authenticatedAt: Date.now(),
    });
  });

  test('isAuthenticated returns true for authenticated peer', () => {
    expect(authenticator.isAuthenticated('peer-1')).toBe(true);
  });

  test('isAuthenticated returns false for unknown peer', () => {
    expect(authenticator.isAuthenticated('unknown')).toBe(false);
  });

  test('getSession returns session for authenticated peer', () => {
    const session = authenticator.getSession('peer-1');

    expect(session).toBeDefined();
    expect(session.publicKey).toBeDefined();
    expect(session.sessionKey).toBeDefined();
  });

  test('getSession returns null for unknown peer', () => {
    const session = authenticator.getSession('unknown');
    expect(session).toBeNull();
  });

  test('revokeSession removes session', () => {
    authenticator.revokeSession('peer-1');

    expect(authenticator.sessions.has('peer-1')).toBe(false);
    expect(authenticator.isAuthenticated('peer-1')).toBe(false);
  });

  test('revokeSession emits session-revoked event', () => {
    const handler = vi.fn();
    authenticator.on('session-revoked', handler);

    authenticator.revokeSession('peer-1');

    expect(handler).toHaveBeenCalledWith({ peerId: 'peer-1' });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// BLOCK/UNBLOCK TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('MeshAuthenticator Block/Unblock', () => {
  let authenticator;
  let mockIdentity;

  beforeEach(() => {
    mockIdentity = createMockIdentity();
    authenticator = new MeshAuthenticator(mockIdentity);

    // Create a session
    authenticator.sessions.set('peer-to-block', {
      publicKey: bytesToHex(randomBytes(32)),
      sessionKey: randomBytes(32),
      authenticatedAt: Date.now(),
    });
  });

  test('block adds peer to blocklist', () => {
    authenticator.block('bad-peer');

    expect(authenticator.options.blocklist.has('bad-peer')).toBe(true);
  });

  test('block revokes existing session', () => {
    authenticator.block('peer-to-block');

    expect(authenticator.sessions.has('peer-to-block')).toBe(false);
  });

  test('blocked peer is not allowed', () => {
    authenticator.block('bad-peer');

    expect(authenticator.isAllowed('bad-peer')).toBe(false);
  });

  test('unblock removes peer from blocklist', () => {
    authenticator.block('temp-blocked');
    authenticator.unblock('temp-blocked');

    expect(authenticator.options.blocklist.has('temp-blocked')).toBe(false);
  });

  test('unblocked peer is allowed', () => {
    authenticator.block('temp-blocked');
    authenticator.unblock('temp-blocked');

    expect(authenticator.isAllowed('temp-blocked')).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// STATS TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('MeshAuthenticator getStats', () => {
  let authenticator;
  let mockIdentity;

  beforeEach(() => {
    mockIdentity = createMockIdentity();
    authenticator = new MeshAuthenticator(mockIdentity);
  });

  test('returns all stats', () => {
    const stats = authenticator.getStats();

    expect(stats.authAttempts).toBeDefined();
    expect(stats.authSuccess).toBeDefined();
    expect(stats.authFailed).toBeDefined();
    expect(stats.blocked).toBeDefined();
  });

  test('includes pending challenges count', () => {
    authenticator.generateChallenge('peer-1');
    authenticator.generateChallenge('peer-2');

    const stats = authenticator.getStats();

    expect(stats.pendingChallenges).toBe(2);
  });

  test('includes active sessions count', () => {
    authenticator.sessions.set('peer-1', {});
    authenticator.sessions.set('peer-2', {});
    authenticator.sessions.set('peer-3', {});

    const stats = authenticator.getStats();

    expect(stats.activeSessions).toBe(3);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

describe('MeshAuthenticator Full Authentication Flow', () => {
  test('complete challenge-response authentication', () => {
    const aliceIdentity = createMockIdentity('alice');
    const bobIdentity = createMockIdentity('bob');

    const alice = new MeshAuthenticator(aliceIdentity);
    const bob = new MeshAuthenticator(bobIdentity);

    // Alice challenges Bob
    const challenge = alice.generateChallenge('bob');
    expect(challenge.type).toBe('auth_challenge');

    // Bob responds to challenge
    const response = bob.respondToChallenge(challenge);
    expect(response.type).toBe('auth_response');
    expect(response.responderNodeId).toBe('bob');

    // Alice verifies Bob's response
    const result = alice.verifyResponse(response);
    expect(result.valid).toBe(true);
    expect(result.peerId).toBe('bob');

    // Bob is now authenticated with Alice
    expect(alice.isAuthenticated('bob')).toBe(true);
    expect(alice.getSession('bob')).toBeDefined();
  });

  test('mutual authentication', () => {
    const aliceIdentity = createMockIdentity('alice');
    const bobIdentity = createMockIdentity('bob');

    const alice = new MeshAuthenticator(aliceIdentity);
    const bob = new MeshAuthenticator(bobIdentity);

    // Alice challenges Bob
    const challengeAtoB = alice.generateChallenge('bob');
    const responseB = bob.respondToChallenge(challengeAtoB);
    alice.verifyResponse(responseB);

    // Bob challenges Alice
    const challengeBtoA = bob.generateChallenge('alice');
    const responseA = alice.respondToChallenge(challengeBtoA);
    bob.verifyResponse(responseA);

    // Both authenticated
    expect(alice.isAuthenticated('bob')).toBe(true);
    expect(bob.isAuthenticated('alice')).toBe(true);
  });
});
