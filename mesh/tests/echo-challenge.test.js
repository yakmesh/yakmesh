import { describe, test, expect } from 'vitest';
import {
  EchoChallenge, workSha3Chain,
} from '../echo-challenge.js';
import {
  generateKeyPair, generateNodeId, signMessage, setCodebaseHash,
} from '../../identity/node-key.js';
import { hexToBytes } from '@noble/hashes/utils.js';

setCodebaseHash('a'.repeat(64));

const mkIdentity = (fill) => {
  const kp = generateKeyPair(new Uint8Array(32).fill(fill));
  return { kp, nodeId: generateNodeId(hexToBytes(kp.publicKey)) };
};

const A = mkIdentity(10); // challenger
const B = mkIdentity(20); // responder
const C = mkIdentity(30); // evil

// A linked pair: each side's send() delivers into the other's handler.
function linkedPair(overrides = {}) {
  const chal = new EchoChallenge({
    nodeId: A.nodeId, publicKey: A.kp.publicKey,
    sign: (d) => signMessage(d, A.kp.secretKey),
    send: (peerId, msg) => {
      if (msg.type === 'echo:challenge') resp.handleChallenge(msg);
      else if (msg.type === 'echo:result') chal.handleResult(msg);
      else if (msg.type === 'echo:refusal') chal.handleRefusal(msg);
    },
    ...(overrides.challenger || {}),
  });
  const resp = new EchoChallenge({
    nodeId: B.nodeId, publicKey: B.kp.publicKey,
    sign: (d) => signMessage(d, B.kp.secretKey),
    send: (peerId, msg) => {
      if (msg.type === 'echo:result') chal.handleResult(msg);
      else if (msg.type === 'echo:refusal') chal.handleRefusal(msg);
    },
    ...(overrides.responder || {}),
  });
  return { chal, resp };
}

describe('workSha3Chain', () => {
  test('deterministic and identity-bound', () => {
    const nonce = 'ab'.repeat(32);
    const r1 = workSha3Chain(nonce, B.nodeId, 64);
    const r2 = workSha3Chain(nonce, B.nodeId, 64);
    expect(r1).toBe(r2);
    expect(r1).toMatch(/^[0-9a-f]{64}$/);
    // Different responder id → different chain (non-transferable)
    expect(workSha3Chain(nonce, C.nodeId, 64)).not.toBe(r1);
    // Different nonce → different chain (no precompute)
    expect(workSha3Chain('cd'.repeat(32), B.nodeId, 64)).not.toBe(r1);
    // Different rounds → different result
    expect(workSha3Chain(nonce, B.nodeId, 65)).not.toBe(r1);
  });
});

describe('EchoChallenge', () => {
  test('challenge → result round trip verifies and measures', async () => {
    const { chal } = linkedPair();
    let measured = null;
    chal.on('measured', (m) => { measured = m; });
    const id = chal.challenge(B.nodeId, { type: 'sha3chain', rounds: 256 });
    expect(id).toBeTruthy();
    await new Promise(r => setTimeout(r, 50));
    expect(measured).not.toBeNull();
    expect(measured.peerId).toBe(B.nodeId);
    expect(measured.work.rounds).toBe(256);
    expect(measured.computeNs).toBeGreaterThan(0);
    expect(chal.stats.verified).toBe(1);
    expect(chal.peerSamples(B.nodeId)).toHaveLength(1);
  });

  test('forged result is rejected as failed', async () => {
    const { chal } = linkedPair({
      responder: {
        executor: async (work, nonce, responderId) => ({
          result: 'ff'.repeat(32), // lie
          procNs: 1000n,
        }),
      },
    });
    let failed = null;
    chal.on('failed', (f) => { failed = f; });
    chal.challenge(B.nodeId, { type: 'sha3chain', rounds: 64 });
    await new Promise(r => setTimeout(r, 30));
    expect(failed?.reason).toBe('bad-result');
    expect(chal.stats.verified).toBe(0);
  });

  test('unbound pubkey (sybil responder) is rejected', async () => {
    const { chal } = linkedPair({
      responder: {
        executor: async (work, nonce) => ({
          // C answers B's challenge with B's correct result but signs as C.
          result: workSha3Chain(nonce, B.nodeId, work.rounds),
          procNs: 1n,
        }),
        publicKey: C.kp.publicKey,
        sign: (d) => signMessage(d, C.kp.secretKey),
        // nodeId stays B — the response will claim B but sign as C:
      },
    });
    // nodeId B + C's pubkey → binding check fails
    let failed = null;
    chal.on('failed', (f) => { failed = f; });
    chal.challenge(B.nodeId, { type: 'sha3chain', rounds: 64 });
    await new Promise(r => setTimeout(r, 30));
    expect(chal.stats.verified).toBe(0);
    // 'failed' via binding — or nonce/from mismatch
    expect(chal.stats.failed).toBeGreaterThan(0);
  });

  test('work-mismatch (responder claims fewer rounds) fails', async () => {
    const { chal, resp } = linkedPair();
    let failed = null;
    chal.on('failed', (f) => { failed = f; });
    // Responder echoes different work AND re-signs — binding must pass
    // so the failure is specifically the work mismatch.
    const origSend = resp.send;
    resp.send = (peerId, msg) => {
      if (msg.type === 'echo:result') {
        msg.work = { ...msg.work, rounds: 1 };
        msg.sig = signMessage(
          JSON.stringify({ ...msg, sig: undefined }), B.kp.secretKey);
      }
      origSend(peerId, msg);
    };
    chal.challenge(B.nodeId, { type: 'sha3chain', rounds: 64 });
    await new Promise(r => setTimeout(r, 30));
    expect(failed?.reason).toBe('work-mismatch');
  });

  test('oversize inbound work is refused, not executed', async () => {
    const { chal, resp } = linkedPair();
    let refused = null;
    chal.on('refused', (r) => { refused = r; });
    chal.challenge(B.nodeId, { type: 'sha3chain', rounds: 999999999 });
    await new Promise(r => setTimeout(r, 30));
    expect(refused?.reason).toBe('oversize');
    expect(resp.stats.served).toBe(0);
  });

  test('unsupported work type refused honestly', async () => {
    const { chal } = linkedPair();
    let refused = null;
    chal.on('refused', (r) => { refused = r; });
    chal.challenge(B.nodeId, { type: 'mkc', script: [] });
    await new Promise(r => setTimeout(r, 30));
    expect(refused?.reason).toBe('unsupported');
  });

  test('mkc-sha3batch: bridge batch verifies bit-exact, device reported', async () => {
    // Fake bridge answers real noble digests — the same bit-exact
    // contract the real MKC guarantees across CPU/GPU/NPU.
    const { sha3_256 } = await import('@noble/hashes/sha3.js');
    const fakeMkc = {
      isAvailable: async () => true,
      sha3_256Batch: async (msgs) => ({
        digests: msgs.map(m => sha3_256(m)), device: 'npu',
      }),
    };
    const { chal } = linkedPair({ responder: { mkc: fakeMkc } });
    let measured = null;
    chal.on('measured', (m) => { measured = m; });
    chal.challenge(B.nodeId, { type: 'mkc-sha3batch', count: 8 });
    await new Promise(r => setTimeout(r, 50));
    expect(measured).not.toBeNull();
    expect(measured.device).toBe('npu');
    expect(measured.work.count).toBe(8);
    expect(chal.stats.verified).toBe(1);
  });

  test('mkc-sha3batch: bridge unreachable → honest unavailable refusal', async () => {
    const { chal } = linkedPair({
      responder: { mkc: { isAvailable: async () => false } },
    });
    let refused = null;
    chal.on('refused', (r) => { refused = r; });
    chal.challenge(B.nodeId, { type: 'mkc-sha3batch', count: 8 });
    await new Promise(r => setTimeout(r, 30));
    expect(refused?.reason).toBe('unavailable');
    expect(chal.stats.verified).toBe(0);
  });

  test('mkc-sha3batch: oversized count refused', async () => {
    const { chal } = linkedPair({
      responder: { mkc: { isAvailable: async () => true } },
    });
    let refused = null;
    chal.on('refused', (r) => { refused = r; });
    chal.challenge(B.nodeId, { type: 'mkc-sha3batch', count: 99999 });
    await new Promise(r => setTimeout(r, 30));
    expect(refused?.reason).toBe('oversize');
  });

  test('per-peer cooldown rate-limits inbound challenges', async () => {
    const { chal, resp } = linkedPair();
    chal.challenge(B.nodeId, { type: 'sha3chain', rounds: 16 });
    await new Promise(r => setTimeout(r, 30));
    // Second challenge inside the cooldown window → refused
    chal.challenge(B.nodeId, { type: 'sha3chain', rounds: 16 });
    await new Promise(r => setTimeout(r, 30));
    expect(resp.stats.refused).toBe(1);
    expect(resp.stats.served).toBe(1);
  });

  test('envelope violation emits anomaly', async () => {
    const { chal } = linkedPair({
      challenger: {
        envelopeFor: () => ({ minNs: 999_000_000_000n, maxNs: 1_000_000_000_000n }),
      },
    });
    let anomaly = null;
    chal.on('anomaly', (a) => { anomaly = a; });
    chal.challenge(B.nodeId, { type: 'sha3chain', rounds: 16 });
    await new Promise(r => setTimeout(r, 30));
    expect(anomaly?.band).toBe('fast');
    expect(chal.stats.verified).toBe(1); // measured anyway — anomaly ≠ failure
  });

  test('timeout fires when no response', async () => {
    const chal = new EchoChallenge({
      nodeId: A.nodeId, publicKey: A.kp.publicKey,
      sign: (d) => signMessage(d, A.kp.secretKey),
      send: () => {}, // black hole
      config: { challengeTimeoutMs: 20 },
    });
    let timeout = null;
    chal.on('timeout', (t) => { timeout = t; });
    chal.challenge(B.nodeId, { type: 'sha3chain', rounds: 16 });
    await new Promise(r => setTimeout(r, 60));
    expect(timeout?.peerId).toBe(B.nodeId);
    expect(chal.stats.timeouts).toBe(1);
  });

  test('malformed inbound messages never throw', async () => {
    const { chal, resp } = linkedPair();
    const junk = [
      null, undefined, {}, { v: 99 },
      { v: 1, from: 'x', id: 'zz', nonce: 'nothex' },
      { v: 1, from: B.nodeId, id: 'aa', nonce: 'bb'.repeat(32), pubKey: 'x', sig: 'y' },
    ];
    for (const j of junk) {
      await resp.handleChallenge(j);
      chal.handleResult(j);
      chal.handleRefusal(j);
    }
    expect(resp.stats.served).toBe(0);
  });

  test('net median adjustment subtracts baseline', async () => {
    const { chal } = linkedPair({
      challenger: { netMedianNs: () => 5_000_000n }, // 5ms network baseline
    });
    let measured = null;
    chal.on('measured', (m) => { measured = m; });
    // Enough rounds that compute exceeds the 5ms baseline → real subtraction.
    chal.challenge(B.nodeId, { type: 'sha3chain', rounds: 8192 });
    await new Promise(r => setTimeout(r, 200));
    expect(measured).not.toBeNull();
    expect(measured.adjusted).toBe(true);
    expect(measured.netNs).toBe(5_000_000);
    expect(measured.computeNs).toBeLessThan(measured.rttNs);
  });
});

// ─── wireEcho: full mesh-transport integration ───────────────────────────

import { wireEcho } from '../echo-challenge.js';

function fakeMesh(nodeId, meshes) {
  const handlers = new Map();
  const mesh = {
    peers: new Map(),
    sendTo(peerId, msg) {
      const target = meshes.get(peerId);
      if (target) target._deliver(msg, nodeId);
    },
    on(type, fn) {
      if (!handlers.has(type)) handlers.set(type, []);
      handlers.get(type).push(fn);
    },
    _deliver(msg, senderNodeId) {
      for (const h of handlers.get(msg.type) || []) h(msg, null, senderNodeId);
    },
  };
  return mesh;
}

describe('wireEcho integration', () => {
  test('probe feeds LatencyTracker; challenge round-trips over sendTo', async () => {
    const meshes = new Map();
    const meshA = fakeMesh(A.nodeId, meshes);
    const meshB = fakeMesh(B.nodeId, meshes);
    meshes.set(A.nodeId, meshA);
    meshes.set(B.nodeId, meshB);
    meshA.peers.set(B.nodeId, {});
    meshB.peers.set(A.nodeId, {});

    const a = wireEcho({
      mesh: meshA, nodeId: A.nodeId, publicKey: A.kp.publicKey,
      sign: (d) => signMessage(d, A.kp.secretKey),
      opts: { perPeerCooldownMs: 0 },
    });
    const b = wireEcho({
      mesh: meshB, nodeId: B.nodeId, publicKey: B.kp.publicKey,
      sign: (d) => signMessage(d, B.kp.secretKey),
      opts: { perPeerCooldownMs: 0 },
    });

    // Probe: A → B, response feeds A's tracker
    a.probePeer(B.nodeId);
    await new Promise(r => setTimeout(r, 30));
    const stats = a.echo.peerLatencies.get(B.nodeId)?.getStats();
    expect(stats).not.toBeNull();
    expect(stats.sampleCount).toBe(1);

    // Challenge: A → B, verified + measured on A
    let measured = null;
    a.challenger.on('measured', (m) => { measured = m; });
    a.challengePeer(B.nodeId, { type: 'sha3chain', rounds: 64 });
    await new Promise(r => setTimeout(r, 50));
    expect(measured?.peerId).toBe(B.nodeId);
    expect(a.challenger.stats.verified).toBe(1);
    expect(b.challenger.stats.served).toBe(1);

    a.stop(); b.stop();
  });

  test('double-wire: lifeline probes bucket under the other wire class', async () => {
    const meshes = new Map();
    const meshA = fakeMesh(A.nodeId, meshes);
    const meshB = fakeMesh(B.nodeId, meshes);
    meshes.set(A.nodeId, meshA);
    meshes.set(B.nodeId, meshB);
    // Both peers dual-wired: primary = tun, lifeline = lan
    meshA.peers.set(B.nodeId, { wsVia: 'tun', lifelineWs: { readyState: 1 } });
    meshB.peers.set(A.nodeId, { wsVia: 'tun', lifelineWs: { readyState: 1 } });

    const a = wireEcho({
      mesh: meshA, nodeId: A.nodeId, publicKey: A.kp.publicKey,
      sign: (d) => signMessage(d, A.kp.secretKey),
    });
    const b = wireEcho({
      mesh: meshB, nodeId: B.nodeId, publicKey: B.kp.publicKey,
      sign: (d) => signMessage(d, B.kp.secretKey),
    });

    a.probePeer(B.nodeId);              // primary → tun
    a.probePeer(B.nodeId, 'lifeline');  // lifeline → lan
    await new Promise(r => setTimeout(r, 30));

    // Per-wire baselines: one sample each, not a mixed median
    expect(a.wireLat.get(`${B.nodeId}@tun`)?.getStats()?.sampleCount).toBe(1);
    expect(a.wireLat.get(`${B.nodeId}@lan`)?.getStats()?.sampleCount).toBe(1);

    // A challenge rides primary → wire 'tun', subtracted from the tun baseline
    let measured = null;
    a.challenger.on('measured', (m) => { measured = m; });
    a.challengePeer(B.nodeId, { type: 'sha3chain', rounds: 32 });
    await new Promise(r => setTimeout(r, 50));
    expect(measured?.wire).toBe('tun');
    expect(measured?.adjusted).toBe(true); // tun baseline existed

    a.stop(); b.stop();
  });
});
