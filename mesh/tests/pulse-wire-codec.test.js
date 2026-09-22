/**
 * Wire-codec regression: signatures travel base64 (no hexes on the wire),
 * verifiers decode both encodings. Guards the ~33% per-beat size win that
 * keeps 1Hz PULSE gossip from saturating WAN links.
 */
import { describe, test, expect } from 'vitest';
import { Heartbeat } from '../pulse-sync.js';
import { signatureToWire } from '../../identity/node-key.js';

const HEX_SIG = 'ab'.repeat(3309); // ML-DSA-65 size in hex chars
const B64_SIG = Buffer.from(HEX_SIG, 'hex').toString('base64');

describe('signatureToWire', () => {
  test('hex converts to base64 (round-trips to same bytes)', () => {
    const out = signatureToWire(HEX_SIG);
    expect(out).toBe(B64_SIG);
    expect(out.length).toBe(4412); // 3309 bytes → 4412 b64 chars vs 6618 hex
  });

  test('non-hex input passes through untouched', () => {
    expect(signatureToWire('mock-sig-abc')).toBe('mock-sig-abc');
    expect(signatureToWire(null)).toBe(null);
    expect(signatureToWire(undefined)).toBe(undefined);
    expect(signatureToWire('abc')).toBe('abc'); // odd length — not hex bytes
  });
});

describe('Heartbeat wire encoding', () => {
  test('serialize emits base64 signature', () => {
    const hb = new Heartbeat({
      nodeId: 'node-test-pq-ABCD',
      sequence: 7,
      meshState: { contribution: { epoch: 42 } },
      signature: HEX_SIG,
    });
    const s = hb.serialize();
    expect(s.signature).toBe(B64_SIG);
    // Hash is computed over content fields only — encoding change is inert
    expect(s.hash).toBe(hb.hash);
    expect(hb.verify()).toBe(true);
  });

  test('deserialize preserves wire signature for verification', () => {
    const hb = new Heartbeat({
      nodeId: 'node-test-pq-ABCD',
      sequence: 7,
      meshState: { x: 1 },
      signature: HEX_SIG,
    });
    const s = hb.serialize();
    const back = Heartbeat.deserialize(s);
    expect(back.signature).toBe(B64_SIG); // wire form retained for dual-mode verify
    expect(back.hash).toBe(hb.hash);
  });
});

describe('ANNEX wrapper — no stacked hop signatures', () => {
  test('sendOn emits a bare annex wrapper (envelope.signature only)', async () => {
    const { default: Annex } = await import('../annex.js');
    const sent = [];
    const annex = new Annex({
      identity: {
        identity: { nodeId: 'node-test-pq-SELF' },
        sign: () => 'ab'.repeat(3309),
      },
      mesh: null,
    });
    annex.sessions.set('node-test-pq-PEER', {
      established: true,
      isExpired: () => false,
      sessionId: 'sess-1',
      encrypt: () => ({ sequence: 1, nonce: 'n'.repeat(24), ciphertext: 'AAAA', authTag: 'BBBB' }),
    });
    const ws = { readyState: 1, send: (s) => sent.push(s) };

    annex.sendOn('node-test-pq-PEER', { type: 'test' }, ws);

    const frame = JSON.parse(sent[0]);
    expect(frame.type).toBe('annex');
    expect(frame.annex.signature).toBe(Buffer.from('ab'.repeat(3309), 'hex').toString('base64'));
    // The redundant hop layer is gone — envelope.signature is the sole auth
    expect(frame._signature).toBeUndefined();
    expect(frame._tribhujSig).toBeUndefined();
    expect(frame._tribhujCert).toBeUndefined();
    expect(frame._tribhujPubKey).toBeUndefined();
  });
});
