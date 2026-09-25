import { describe, test, expect } from 'vitest';
import {
  claimsStreamId, claimSetBytes, parseClaimSet, ClaimDurability,
} from '../claim-durability.js';
import { ClaimLedger } from '../claim-ledger.js';
import { TemporalMeshEncoder } from '../temporal-encoder.js';
import { claimLeafHash } from '../attestation-gossip.js';

const claim = (over = {}) => ({
  version: 1, epoch: 7, yakmeshNodeId: 'peer-alpha', nodeId: 'ab'.repeat(32),
  seal: [0, 1, 2, 3], spongeRounds: 12, shareCount: 5,
  jobRoot: 'cd'.repeat(32), entropyFlags: 3, siliconDrift: 1,
  verified: 'verified', ...over,
});

const ledgerWith = (claims) => ({
  epochClaims: () => claims,
  forks: [], bindingConflicts: [],
});

describe('claimSetBytes / parseClaimSet', () => {
  test('round-trips claims byte-exactly', () => {
    const claims = [
      claim({ yakmeshNodeId: 'peer-b', nodeId: 'bb'.repeat(32) }),
      claim({ yakmeshNodeId: 'peer-a', nodeId: 'aa'.repeat(32) }),
    ];
    const buf = claimSetBytes(7, claims);
    const parsed = parseClaimSet(buf);
    expect(parsed.epoch).toBe(7);
    expect(parsed.rejected).toBe(0);
    expect(parsed.truncated).toBe(false);
    expect(parsed.claims).toHaveLength(2);
    // Sorted by nodeId — 'aa' before 'bb'
    expect(parsed.claims[0].nodeId).toBe('aa'.repeat(32));
    expect(parsed.claims[0].yakmeshNodeId).toBe('peer-a');
    expect(parsed.claims[0].shareCount).toBe(5);
    expect(parsed.claims[0].spongeRounds).toBe(12);
    expect(parsed.claims[0].seal).toEqual([0, 1, 2, 3]);
    // Leaf recomputes identically
    expect(claimLeafHash(parsed.claims[0])).toBe(claimLeafHash(claims[1]));
  });

  test('flipped leaf byte yields a different leaf (cross-check surface)', () => {
    // The leaf IS the payload — parse can't detect content corruption
    // alone; the defense is claimLeafHash divergence vs attested leaves
    // (and the TME slice hash-chain below). Verify that surface exists.
    const orig = claimSetBytes(7, [claim()]);
    const buf = Buffer.from(orig);
    buf[buf.length - 40] ^= 0xff;
    const parsed = parseClaimSet(buf);
    expect(parsed.claims).toHaveLength(1);
    expect(claimLeafHash(parsed.claims[0])).not.toBe(claimLeafHash(claim()));
  });

  test('truncated buffer flags truncation, never throws', () => {
    const buf = claimSetBytes(7, [claim()]);
    const parsed = parseClaimSet(buf.subarray(0, buf.length - 30));
    expect(parsed.truncated).toBe(true);
    expect(parsed.claims).toHaveLength(0);
  });

  test('malformed input rejected cleanly', () => {
    expect(parseClaimSet(Buffer.alloc(3)).rejected).toBe(1);
    expect(parseClaimSet(null).rejected).toBe(1);
    const bad = claimSetBytes(7, [claim()]);
    bad.writeUInt8(9, 0); // wrong version
    expect(parseClaimSet(bad).rejected).toBe(1);
  });

  test('epoch inside a leaf must match the set header', () => {
    const buf = claimSetBytes(7, [claim({ epoch: 9 })]); // claim lies about epoch
    const parsed = parseClaimSet(buf);
    expect(parsed.rejected).toBe(1);
  });
});

describe('claimsStreamId', () => {
  test('deterministic and distinct per (epoch, witness)', () => {
    const a = claimsStreamId(7, 'node-x');
    expect(a).toBe(claimsStreamId(7, 'node-x'));
    expect(a).not.toBe(claimsStreamId(8, 'node-x'));
    expect(a).not.toBe(claimsStreamId(7, 'node-y'));
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('ClaimDurability', () => {
  const mkTransport = () => {
    const t = {
      dispatched: [],
      dispatchSlices: (enc) => {
        t.dispatched.push(enc);
        return { dispatched: enc.slices.length };
      },
      requestReconstruction: () => {},
    };
    return t;
  };

  test('encodeEpoch disperses the witnessed claim set', () => {
    const encoder = new TemporalMeshEncoder({ nodeId: 'us' });
    const transport = mkTransport();
    const dur = new ClaimDurability({
      nodeId: 'us', claimLedger: ledgerWith([claim(), claim({ nodeId: 'cd'.repeat(32) })]),
      encoder, transport,
    });
    const r = dur.encodeEpoch(7);
    expect(r.claims).toBe(2);
    expect(r.streamId).toBe(claimsStreamId(7, 'us'));
    expect(transport.dispatched).toHaveLength(1);
    // Deterministic stream registered in outbound
    expect(encoder.outboundStreams.has(r.streamId)).toBe(true);
  });

  test('empty epoch encodes nothing', () => {
    const dur = new ClaimDurability({
      nodeId: 'us', claimLedger: ledgerWith([]),
      encoder: new TemporalMeshEncoder({ nodeId: 'us' }),
    });
    expect(dur.encodeEpoch(7)).toBeNull();
  });

  test('full loop: encode → slices → remote encoder → assemble', () => {
    const claims = [
      claim({ nodeId: 'aa'.repeat(32) }),
      claim({ nodeId: 'bb'.repeat(32), yakmeshNodeId: 'peer-b', shareCount: 9 }),
    ];
    const srcEnc = new TemporalMeshEncoder({ nodeId: 'us' });
    const dstEnc = new TemporalMeshEncoder({ nodeId: 'them' });
    const dur = new ClaimDurability({
      nodeId: 'us', claimLedger: ledgerWith(claims), encoder: srcEnc,
    });
    const r = dur.encodeEpoch(7);
    const enc = srcEnc.outboundStreams.get(r.streamId);

    // Simulate remote receive: metadata init + all slices
    dstEnc.initReceive({
      streamId: r.streamId, totalSlices: enc.totalSlices,
      sliceSize: enc.sliceSize,
      baseTimestamp: enc.baseTimestamp.toString(),
      sliceIntervalNs: enc.sliceIntervalNs,
    });
    for (const [, s] of enc.slices) {
      expect(dstEnc.receiveSlice(s.serialize()).accepted).toBe(true);
    }

    const dur2 = new ClaimDurability({
      nodeId: 'them', claimLedger: ledgerWith([]), encoder: dstEnc,
    });
    const got = dur2.assemble(r.streamId);
    expect(got.success).toBe(true);
    expect(got.claims).toHaveLength(2);
    expect(got.claims.map(c => c.nodeId).sort())
      .toEqual(claims.map(c => c.nodeId).sort());
    expect(claimLeafHash(got.claims[1])).toBe(claimLeafHash(claims[1]));
  });

  test('assemble flags claims never attested', () => {
    const claims = [claim({ nodeId: 'aa'.repeat(32) })];
    const srcEnc = new TemporalMeshEncoder({ nodeId: 'us' });
    const dstEnc = new TemporalMeshEncoder({ nodeId: 'them' });
    const dur = new ClaimDurability({
      nodeId: 'us', claimLedger: ledgerWith(claims), encoder: srcEnc,
    });
    const r = dur.encodeEpoch(7);
    const enc = srcEnc.outboundStreams.get(r.streamId);
    dstEnc.initReceive({
      streamId: r.streamId, totalSlices: enc.totalSlices,
      sliceSize: enc.sliceSize,
      baseTimestamp: enc.baseTimestamp.toString(),
      sliceIntervalNs: enc.sliceIntervalNs,
    });
    for (const [, s] of enc.slices) dstEnc.receiveSlice(s.serialize());

    // AttestGossip stub whose claimRefs hold a DIFFERENT leaf — the
    // recovered claim was never attested by anyone we heard.
    const fakeAttest = {
      claimRefs: new Map([['k', { leaf: 'ff'.repeat(32) }]]),
    };
    const dur2 = new ClaimDurability({
      nodeId: 'them', claimLedger: ledgerWith([]),
      encoder: dstEnc, attestGossip: fakeAttest,
    });
    let anomaly = null;
    dur2.on('recoveryAnomaly', (a) => { anomaly = a; });
    const got = dur2.assemble(r.streamId);
    expect(got.unattested).toBe(1);
    expect(got.claims[0].unattested).toBe(true);
    expect(anomaly.unattested).toBe(1);
  });

  test('prune drops streams past the retention horizon', () => {
    const encoder = new TemporalMeshEncoder({ nodeId: 'us' });
    const dur = new ClaimDurability({
      nodeId: 'us', claimLedger: ledgerWith([claim()]), encoder,
    });
    dur.encodeEpoch(7);
    const oldId = claimsStreamId(7, 'us');
    expect(encoder.outboundStreams.has(oldId)).toBe(true);
    // Encoding epoch 200 prunes epoch 7 (horizon 64)
    dur.encodeEpoch(200);
    expect(dur.encoded.has(7)).toBe(false);
    expect(encoder.outboundStreams.has(oldId)).toBe(false);
  });
});
