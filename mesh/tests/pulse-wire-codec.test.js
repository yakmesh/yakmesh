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
