import { describe, test, expect } from 'vitest';
import { BANDS, bandFor, envelopeFor, benchmark } from '../capability-bands.js';
import { EchoChallenge, wireEcho } from '../echo-challenge.js';
import {
  generateKeyPair, generateNodeId, signMessage, setCodebaseHash,
} from '../../identity/node-key.js';
import { hexToBytes } from '@noble/hashes/utils.js';

setCodebaseHash('a'.repeat(64));

const mkIdentity = (fill) => {
  const kp = generateKeyPair(new Uint8Array(32).fill(fill));
  return { kp, nodeId: generateNodeId(hexToBytes(kp.publicKey)) };
};
const A = mkIdentity(40);
const B = mkIdentity(50);

describe('bandFor / envelopeFor', () => {
  test('classifies ns/unit into ordered bands per work type', () => {
    expect(bandFor(100, 'sha3chain')).toBe('auric');
    expect(bandFor(1500, 'sha3chain')).toBe('silver');
    expect(bandFor(7000, 'sha3chain')).toBe('copper');
    expect(bandFor(50000, 'sha3chain')).toBe('ferrous');
    expect(bandFor(999999, 'sha3chain')).toBe('ferrous'); // slowest floor
    expect(bandFor(50_000, 'mkc-sha3batch')).toBe('auric');
    expect(bandFor(400_000, 'mkc-sha3batch')).toBe('copper');
  });

  test('envelope scales by work units with tolerance', () => {
    const env = envelopeFor({ type: 'sha3chain', rounds: 1000 }, 'copper');
    const [lo, hi] = BANDS.sha3chain.copper;
    expect(env.minNs).toBe(BigInt(Math.floor(lo * 0.5)) * 1000n);
    expect(env.maxNs).toBe(BigInt(Math.ceil(hi * 2)) * 1000n);
    expect(env.band).toBe('copper');
  });

  test('envelope resolves the work-type key of a declared band map', () => {
    const decl = { sha3chain: 'copper', 'mkc-sha3batch': 'auric' };
    const env = envelopeFor({ type: 'mkc-sha3batch', count: 64 }, decl);
    expect(env.band).toBe('auric');
    expect(env.minNs).toBe(BigInt(Math.floor(10_000 * 0.5)) * 64n);
    // Map holds no band for this work type → no envelope (unclassified)
    expect(envelopeFor({ type: 'sha3chain', rounds: 1 },
                       { 'mkc-sha3batch': 'auric' })).toBeNull();
  });

  test('unknown band or work type → null envelope', () => {
    expect(envelopeFor({ type: 'sha3chain', rounds: 1 }, 'unobtanium')).toBeNull();
    expect(envelopeFor({ type: 'avoth' }, 'copper')).toBeNull();
    expect(envelopeFor({ type: 'sha3chain', rounds: 1 }, null)).toBeNull();
  });
});

describe('benchmark', () => {
  test('measures sha3chain; mkc band when injected bridge answers', async () => {
    const fakeMkc = {
      isAvailable: async () => true,
      sha3_256Batch: async (msgs) => ({
        digests: msgs.map(() => new Uint8Array(32)), device: 'npu',
      }),
    };
    const b = await benchmark(256, 2, 'bench-node', fakeMkc);
    expect(b.bands.sha3chain).toBeDefined();
    expect(b.measured.sha3chain.nsPerUnit).toBeGreaterThan(0);
    expect(b.bands['mkc-sha3batch']).toBeDefined();
    expect(b.measured['mkc-sha3batch'].device).toBe('npu');
  });

  test('bridge unreachable → mkc band absent, honest non-declaration', async () => {
    const fakeMkc = { isAvailable: async () => false };
    const b = await benchmark(128, 2, 'bench-node', fakeMkc);
    expect(b.bands.sha3chain).toBeDefined();
    expect(b.bands['mkc-sha3batch']).toBeUndefined();
  });
});

describe('band declaration → conformance loop', () => {
  test('verified result stores the peer declared band map', async () => {
    const chal = new EchoChallenge({
      nodeId: A.nodeId, publicKey: A.kp.publicKey,
      sign: (d) => signMessage(d, A.kp.secretKey),
      send: (peerId, msg) => resp.handleChallenge(msg),
    });
    const resp = new EchoChallenge({
      nodeId: B.nodeId, publicKey: B.kp.publicKey,
      sign: (d) => signMessage(d, B.kp.secretKey),
      bandHint: { sha3chain: 'copper', 'mkc-sha3batch': 'silver' },
      send: (peerId, msg) => chal.handleResult(msg),
    });
    chal.challenge(B.nodeId, { type: 'sha3chain', rounds: 32 });
    await new Promise(r => setTimeout(r, 50));
    expect(chal.peerBands.get(B.nodeId))
      .toEqual({ sha3chain: 'copper', 'mkc-sha3batch': 'silver' });
  });

  test('declared-band envelope classifies via wireEcho', async () => {
    // Fake mesh pair (same harness as echo-challenge tests)
    const meshes = new Map();
    const fakeMesh = (nodeId) => {
      const handlers = new Map();
      return {
        peers: new Map(),
        sendTo(peerId, msg) {
          meshes.get(peerId)?._deliver(msg, nodeId);
        },
        on(type, fn) {
          if (!handlers.has(type)) handlers.set(type, []);
          handlers.get(type).push(fn);
        },
        _deliver(msg, sender) {
          for (const h of handlers.get(msg.type) || []) h(msg, null, sender);
        },
      };
    };
    const meshA = fakeMesh(A.nodeId);
    const meshB = fakeMesh(B.nodeId);
    meshes.set(A.nodeId, meshA);
    meshes.set(B.nodeId, meshB);
    meshA.peers.set(B.nodeId, { wsVia: 'lan' });
    meshB.peers.set(A.nodeId, { wsVia: 'lan' });

    const a = wireEcho({
      mesh: meshA, nodeId: A.nodeId, publicKey: A.kp.publicKey,
      sign: (d) => signMessage(d, A.kp.secretKey),
      bands: { hint: { sha3chain: 'silver' }, envelopeFor },
      opts: { perPeerCooldownMs: 0 },
    });
    const b = wireEcho({
      mesh: meshB, nodeId: B.nodeId, publicKey: B.kp.publicKey,
      sign: (d) => signMessage(d, B.kp.secretKey),
      bands: { hint: { sha3chain: 'ferrous' }, envelopeFor },
      opts: { perPeerCooldownMs: 0 },
    });

    // First challenge: cold → unclassified, but learns B's 'ferrous'
    a.challengePeer(B.nodeId, { type: 'sha3chain', rounds: 32 });
    await new Promise(r => setTimeout(r, 50));
    expect(a.challenger.peerBands.get(B.nodeId))
      .toEqual({ sha3chain: 'ferrous' });

    // The wired default envelope now resolves the peer's declared band —
    // deterministic check (real-timing classification is covered in
    // echo-challenge tests with synthetic envelopes).
    const env = a.challenger.envelopeFor(B.nodeId, { type: 'sha3chain', rounds: 32 });
    expect(env).not.toBeNull();
    expect(env.band).toBe('ferrous');
    expect(env.minNs).toBeGreaterThan(0n);
    expect(env.maxNs).toBeGreaterThan(env.minNs);

    a.stop(); b.stop();
  });
});
