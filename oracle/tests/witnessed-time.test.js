/**
 * WITNESSED-tier quorum collector tests.
 *
 * Run with: node --test oracle/tests/witnessed-time.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { hexToBytes } from '@noble/hashes/utils.js';
import { WitnessedTime, pulsePreimage, WITNESS_QUORUM_K } from '../witnessed-time.js';
import { generateKeyPair, signMessage, generateNodeId, setCodebaseHash } from '../../identity/node-key.js';

// nodeId derivation requires the codebase binding
setCodebaseHash('a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90');

const EPOCH_MS = 30_000;

function makeAttester(seed) {
  const kp = generateKeyPair(new Uint8Array(32).fill(seed));
  const nodeId = generateNodeId(hexToBytes(kp.publicKey));
  return { kp, nodeId };
}

/** A signed stratum-1 pulse from `attester` claiming remote time `t`. */
function pulse(attester, t, stratum = 1) {
  const epoch = Math.floor(t / EPOCH_MS);
  const pre = pulsePreimage({ nodeId: attester.nodeId, epoch, timestamp: t, stratum });
  return {
    nodeId: attester.nodeId,
    timestamp: t,
    stratum,
    pubKey: attester.kp.publicKey,
    pulseSig: signMessage(pre, attester.kp.secretKey),
  };
}

describe('WitnessedTime', () => {
  it('reaches quorum at k distinct attesters with tight spread', () => {
    const localNow = 1_700_000_000_000;
    const wt = new WitnessedTime({ nodeId: 'self', now: () => localNow });
    const a = [makeAttester(1), makeAttester(2), makeAttester(3)];
    // three attesters all ~120ms ahead of us, small spread
    for (const [i, at] of a.entries()) {
      assert.ok(wt.observePulse(pulse(at, localNow + 120 + i)));
    }
    const st = wt.witnessedState();
    assert.equal(st.eligible, true);
    assert.equal(st.attesters, 3);
    assert.ok(Math.abs(st.offsetMs - 121) <= 1);
    assert.ok(st.boundMs <= 1);
  });

  it('is ineligible below quorum', () => {
    const localNow = 1_700_000_000_000;
    const wt = new WitnessedTime({ nodeId: 'self', now: () => localNow });
    const a = makeAttester(1);
    wt.observePulse(pulse(a, localNow + 50));
    const st = wt.witnessedState();
    assert.equal(st.eligible, false);
    assert.equal(st.attesters, 1);
  });

  it('rejects unsigned / badly-bound pulses', () => {
    const localNow = 1_700_000_000_000;
    const wt = new WitnessedTime({ nodeId: 'self', now: () => localNow });
    const a = makeAttester(1);
    const p = pulse(a, localNow + 50);
    p.pulseSig = 'deadbeef';
    assert.equal(wt.observePulse(p), false);
    // valid sig over the CLAIMED nodeId but pubkey doesn't derive it
    // (sybil shape: own key signing for a minted identity)
    const b = makeAttester(9);
    const t = localNow + 50;
    const epoch = Math.floor(t / EPOCH_MS);
    const forged = {
      nodeId: a.nodeId, timestamp: t, stratum: 1,
      pubKey: b.kp.publicKey,
      pulseSig: signMessage(
        pulsePreimage({ nodeId: a.nodeId, epoch, timestamp: t, stratum: 1 }),
        b.kp.secretKey),
    };
    assert.equal(wt.observePulse(forged), false);
    assert.equal(wt.stats.badBinding, 1);
  });

  it('ignores non-stratum-1 sources and self', () => {
    const localNow = 1_700_000_000_000;
    const wt = new WitnessedTime({ nodeId: 'self', now: () => localNow });
    const a = makeAttester(1);
    assert.equal(wt.observePulse(pulse(a, localNow + 50, 3)), false);
    assert.equal(wt.stats.lowStratum, 1);
    const selfP = pulse(a, localNow + 50);
    selfP.nodeId = 'self';
    // nodeId won't match the key → binding check, but self check runs first
    assert.equal(wt.observePulse(selfP), false);
    assert.equal(wt.stats.self, 1);
  });

  it('rejects an outlier that breaks the bound', () => {
    const localNow = 1_700_000_000_000;
    const wt = new WitnessedTime({ nodeId: 'self', now: () => localNow });
    const ats = [1, 2, 3, 4].map(makeAttester);
    // three agree at +100; one is 4s off → outlier-dropped, quorum holds
    for (const [i, at] of ats.entries()) {
      wt.observePulse(pulse(at, localNow + (i === 3 ? 4000 : 100)));
    }
    const st = wt.witnessedState();
    assert.equal(st.eligible, true);
    assert.equal(st.attesters, 3);
    assert.equal(st.boundMs, 0);
  });

  it('first pulse per attester per epoch wins (no re-send gaming)', () => {
    const localNow = 1_700_000_000_000;
    const wt = new WitnessedTime({ nodeId: 'self', now: () => localNow });
    const a = makeAttester(1);
    wt.observePulse(pulse(a, localNow + 50));
    wt.observePulse(pulse(a, localNow + 999)); // same attester+epoch
    const epochMap = wt.pulses.get(Math.floor(localNow / EPOCH_MS));
    assert.equal(epochMap.size, 1);
    assert.equal(epochMap.get(a.nodeId).offsetMs, localNow + 50 - localNow);
  });
});
