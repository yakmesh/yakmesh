/**
 * SAMUHA admission-control tests
 *
 * Covers: ternary verdicts (ADMIT/HOLD/REDIRECT), weighted priority,
 * eviction upgrade, HOLD queue depth/timeout/promotion, signed referral
 * tokens, and the status surface.
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import { Aguwa, aguwa } from '../aguwa.js';
import { MandalaNetwork, MessageTypes } from '../network.js';
import {
  generateKeyPair,
  signMessage,
  verifySignature,
  generateNodeId,
  setCodebaseHash,
} from '../../identity/node-key.js';
import { hexToBytes } from '@noble/hashes/utils.js';

// ── Helpers ─────────────────────────────────────────────────────────

function fakeWs() {
  return {
    readyState: 1, // WebSocket.OPEN
    sent: [],
    closed: null,
    _clientIp: '127.0.0.1',
    send(data) { this.sent.push(JSON.parse(data)); },
    close(code, reason) { this.closed = { code, reason }; this.readyState = 3; },
  };
}

const stubReq = { socket: { remoteAddress: '127.0.0.1' } };

function makeNet() {
  const identity = {
    identity: { nodeId: 'node-test-self', publicKey: 'aa'.repeat(16) },
    sign: (m) => signMessage(m, selfKeys.secretKey),
    verify: (m, s, pk) => verifySignature(m, s, pk),
    getPublicIdentity: () => ({ nodeId: 'node-test-self', name: 'self' }),
    getPersistentId: () => 'self-persistent',
  };
  return new MandalaNetwork(identity, { wsPort: 0 });
}

const selfKeys = generateKeyPair(new Uint8Array(32).fill(7));

/** Build a fully valid HELLO message for a fresh peer identity. */
function makeHello(seedByte) {
  const keys = generateKeyPair(new Uint8Array(32).fill(seedByte));
  const nodeId = generateNodeId(hexToBytes(keys.publicKey));
  const timestamp = Date.now();
  const tribhujPubKey = 'bb'.repeat(8);
  const proof = signMessage(`YAKMESH:HELLO:${nodeId}:${timestamp}:${tribhujPubKey}`, keys.secretKey);
  return {
    msg: {
      type: MessageTypes.HELLO,
      timestamp,
      proof,
      identity: {
        nodeId,
        publicKey: keys.publicKey,
        tribhujPubKey,
        persistentId: `persist-${seedByte}`,
        name: `peer-${seedByte}`,
      },
      capabilities: { totalTops: 16, maniTrust: 'GPS' },
      advertisedEndpoint: null,
    },
    keys,
    nodeId,
  };
}

// ── AGUWA verdict unit tests ────────────────────────────────────────

describe('SAMUHA admission verdicts (aguwa)', () => {
  test('utilization < 0.8 → ADMIT (+1)', () => {
    const a = new Aguwa();
    const v = a.admissionVerdict({ capabilities: {}, persistentId: null });
    expect(v.verdict).toBe(1);
    expect(v.utilization).toBe(0);
  });

  test('0.8 ≤ utilization < 1.0 → HOLD (0)', () => {
    const a = new Aguwa();
    // maxPeers falls back to 128 without buffer — fill to 103 (0.805)
    for (let i = 0; i < 103; i++) a.peers.set(`p${i}`, { aguwaScore: 0.5 });
    const v = a.admissionVerdict({ capabilities: {}, persistentId: null });
    expect(v.verdict).toBe(0);
    expect(v.utilization).toBeGreaterThanOrEqual(0.8);
    expect(v.utilization).toBeLessThan(1.0);
  });

  test('utilization ≥ 1.0, incoming ≤ lowest → REDIRECT (−1)', () => {
    const a = new Aguwa();
    for (let i = 0; i < 128; i++) a.peers.set(`p${i}`, { aguwaScore: 0.9 });
    const v = a.admissionVerdict({ capabilities: {}, persistentId: null });
    expect(v.verdict).toBe(-1);
    expect(v.lowestPeer).toBeTruthy();
  });

  test('utilization ≥ 1.0, incoming > lowest → eviction upgrade to ADMIT', () => {
    const a = new Aguwa();
    for (let i = 0; i < 128; i++) a.peers.set(`p${i}`, { aguwaScore: 0.9 });
    a.peers.set('weak', { aguwaScore: 0.01 });
    const karmaModel = { getTrustLevel: () => ({ level: 3 }) };
    const v = a.admissionVerdict({
      capabilities: { totalTops: 127, maniTrust: 'ATOMIC' },
      persistentId: 'veteran',
      karmaModel,
    });
    expect(v.verdict).toBe(1);
    expect(v.lowestPeer).toBe('weak');
    expect(a._admissionStats.evictions).toBe(1);
  });

  test('priority formula: 0.3·karma + 0.3·hw + 0.2·returning + 0.2·mani', () => {
    const a = new Aguwa();
    // All-minimal inputs
    const min = a.admissionVerdict({ capabilities: {}, persistentId: null });
    // hw floor 0.1 + mani UNSYNC 0.1 → 0.3*0.1 + 0.2*0.1 = 0.05
    expect(min.priority).toBeCloseTo(0.05, 5);

    const karmaModel = { getTrustLevel: () => ({ level: 3 }) };
    const max = a.admissionVerdict({
      capabilities: { totalTops: 127, maniTrust: 'GPS' },
      persistentId: 'veteran',
      karmaModel,
    });
    // 0.3*1.0 + 0.3*1.0 + 0.2*1.0 + 0.2*0.85 = 0.97
    expect(max.priority).toBeCloseTo(0.97, 5);
  });

  test('verdict tallies accumulate in admissionStatus()', () => {
    const a = new Aguwa();
    a.admissionVerdict({ capabilities: {} });                       // admit
    for (let i = 0; i < 103; i++) a.peers.set(`p${i}`, { aguwaScore: 0.5 });
    a.admissionVerdict({ capabilities: {} });                       // hold
    for (let i = 103; i < 128; i++) a.peers.set(`p${i}`, { aguwaScore: 0.9 });
    a.admissionVerdict({ capabilities: {} });                       // redirect
    const s = a.admissionStatus();
    expect(s.verdicts).toMatchObject({ admit: 1, hold: 1, redirect: 1 });
    expect(s.thresholds).toEqual({ hold: 0.8, redirect: 1.0 });
    expect(s.maxPeers).toBe(128);
    expect(s.activePeers).toBe(128);
  });
});

// ── HOLD queue tests (network layer, real HELLO path) ───────────────

describe('SAMUHA HOLD queue (network)', () => {
  let savedPeers;

  beforeEach(() => {
    setCodebaseHash('samuha-test-codebase');
    savedPeers = aguwa.peers;
    aguwa.peers = new Map();
    aguwa._admissionStats = { admit: 0, hold: 0, redirect: 0, evictions: 0 };
  });

  afterEach(() => {
    aguwa.peers = savedPeers;
    vi.useRealTimers();
  });

  /** Fill aguwa.peers to a given count. */
  function fillPeers(n, score = 0.5) {
    for (let i = aguwa.peers.size; i < n; i++) aguwa.peers.set(`fill-${i}`, { aguwaScore: score });
  }

  test('HOLD band → peer queued, not admitted; HOLD message sent', () => {
    const net = makeNet();
    fillPeers(103); // util ≈ 0.805 → HOLD
    const { msg, nodeId } = makeHello(11);
    const ws = fakeWs();

    net._handleMessage(ws, Buffer.from(JSON.stringify(msg)), stubReq);

    expect(net.peers.has(nodeId)).toBe(false);       // NOT admitted
    expect(net._holdQueue).toHaveLength(1);
    expect(net._holdQueue[0].nodeId).toBe(nodeId);
    const holdMsg = ws.sent.find(m => m.type === MessageTypes.HOLD);
    expect(holdMsg).toBeTruthy();
    expect(holdMsg.position).toBe(1);
    expect(holdMsg.timeoutMs).toBe(30000);
  });

  test('queue depth cap → 11th held peer degrades to REDIRECT', () => {
    const net = makeNet();
    fillPeers(103);
    for (let i = 0; i < 10; i++) {
      const { msg } = makeHello(20 + i);
      net._handleMessage(fakeWs(), Buffer.from(JSON.stringify(msg)), stubReq);
    }
    expect(net._holdQueue).toHaveLength(10);

    const ws = fakeWs();
    const { msg } = makeHello(99);
    net._handleMessage(ws, Buffer.from(JSON.stringify(msg)), stubReq);

    expect(net._holdQueue).toHaveLength(10); // unchanged
    const redirect = ws.sent.find(m => m.type === MessageTypes.REDIRECT);
    expect(redirect).toBeTruthy();
    expect(redirect.reason).toBe('hold_queue_full');
    expect(ws.closed).toBeTruthy();
  });

  test('HOLD timeout → REDIRECT + close', () => {
    vi.useFakeTimers();
    const net = makeNet();
    fillPeers(103);
    const ws = fakeWs();
    const { msg } = makeHello(50);
    net._handleMessage(ws, Buffer.from(JSON.stringify(msg)), stubReq);
    expect(net._holdQueue).toHaveLength(1);

    vi.advanceTimersByTime(30001);

    expect(net._holdQueue).toHaveLength(0);
    const redirect = ws.sent.find(m => m.type === MessageTypes.REDIRECT);
    expect(redirect).toBeTruthy();
    expect(redirect.reason).toBe('hold_timeout');
    expect(ws.closed).toBeTruthy();
  });

  test('slot opens → held peer promoted through normal HELLO path and admitted', () => {
    const net = makeNet();
    fillPeers(102);
    const ws = fakeWs();
    const { msg, nodeId } = makeHello(60);
    net._handleMessage(ws, Buffer.from(JSON.stringify(msg)), stubReq);
    expect(net._holdQueue).toHaveLength(1);

    // A connected peer disconnects → utilization drops below 0.8.
    // The leaver must exist in BOTH stores: net.peers (socket map) and
    // aguwa.peers (utilization count) — production keeps them in sync.
    const peerWs = fakeWs();
    net.peers.set('leaver', { ws: peerWs, identity: { name: 'leaver' } });
    aguwa.peers.set('leaver', { aguwaScore: 0.5 });
    net._handleDisconnect(peerWs);

    // Promotion re-dispatched the stored HELLO → now admitted
    expect(net._holdQueue).toHaveLength(0);
    expect(net.peers.has(nodeId)).toBe(true);
    expect(net.peers.get(nodeId).admission.verdict).toBe(1);
  });

  test('held peer disconnects → entry purged, no promotion attempt', () => {
    const net = makeNet();
    fillPeers(103);
    const ws = fakeWs();
    const { msg } = makeHello(70);
    net._handleMessage(ws, Buffer.from(JSON.stringify(msg)), stubReq);
    expect(net._holdQueue).toHaveLength(1);

    net._handleDisconnect(ws);
    expect(net._holdQueue).toHaveLength(0);
  });

  test('REDIRECT carries a signed referral token', () => {
    const net = makeNet();
    fillPeers(103);
    // Fill the queue so the next peer degrades to REDIRECT
    for (let i = 0; i < 10; i++) {
      const { msg } = makeHello(30 + i);
      net._handleMessage(fakeWs(), Buffer.from(JSON.stringify(msg)), stubReq);
    }
    const ws = fakeWs();
    const { msg, nodeId } = makeHello(80);
    net._handleMessage(ws, Buffer.from(JSON.stringify(msg)), stubReq);

    const redirect = ws.sent.find(m => m.type === MessageTypes.REDIRECT);
    expect(redirect.referral).toBeTruthy();
    expect(redirect.referral.by).toBe('node-test-self');
    expect(redirect.referral.exp).toBeGreaterThan(Date.now());
    // Referral signature verifies under the sender's key
    const ok = verifySignature(
      `YAKMESH:REFERRAL:${nodeId}:${redirect.referral.exp}`,
      redirect.referral.sig,
      selfKeys.publicKey,
    );
    expect(ok).toBe(true);
  });

  test('incoming referral token validated against known referrers', () => {
    const net = makeNet();
    const { msg, nodeId, keys } = makeHello(90);
    // A known referrer signs a referral for this peer
    const exp = Date.now() + 60000;
    msg.referral = {
      by: 'referrer-1',
      exp,
      sig: signMessage(`YAKMESH:REFERRAL:${nodeId}:${exp}`, keys.secretKey),
    };
    net.knownNodes.set('referrer-1', { identity: { publicKey: keys.publicKey } });

    const ws = fakeWs();
    net._handleMessage(ws, Buffer.from(JSON.stringify(msg)), stubReq);
    expect(ws._referralVerified).toBe(true);

    // Forged referral → not verified
    const { msg: msg2, nodeId: nodeId2 } = makeHello(91);
    msg2.referral = { by: 'referrer-1', exp: Date.now() + 60000, sig: 'deadbeef' };
    const ws2 = fakeWs();
    net._handleMessage(ws2, Buffer.from(JSON.stringify(msg2)), stubReq);
    expect(ws2._referralVerified).toBeUndefined();
  });

  test('getSamuhaStatus exposes queue + verdicts', () => {
    const net = makeNet();
    fillPeers(103);
    const { msg } = makeHello(95);
    net._handleMessage(fakeWs(), Buffer.from(JSON.stringify(msg)), stubReq);

    const s = net.getSamuhaStatus();
    expect(s.holdQueue.depth).toBe(1);
    expect(s.holdQueue.maxDepth).toBe(10);
    expect(s.holdQueue.waiting).toHaveLength(1);
    expect(s.verdicts.hold).toBe(1);
    expect(s.thresholds.hold).toBe(0.8);
  });
});
