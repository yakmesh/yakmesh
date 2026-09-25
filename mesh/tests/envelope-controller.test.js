/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 */

/**
 * Envelope-controller tests — the anti-gaming invariants:
 * tighten fast, loosen slow, fixed bounds, hysteresis, per-peer
 * isolation, and detection-only scope (no reward surface).
 *
 * @module mesh/tests/envelope-controller.test
 */

import { describe, test, expect, vi, afterEach } from 'vitest';
import { EnvelopeController, LEVELS } from '../envelope-controller.js';
import { envelopeFor, TOLERANCE } from '../capability-bands.js';

const ok = { band: 'ok' };
const slow = { band: 'slow' };
const work = { type: 'sha3chain', rounds: 4096 };

describe('EnvelopeController — fuse model', () => {
  test('starts normal at the static baseline', () => {
    const c = new EnvelopeController();
    expect(c.levelFor('peer')).toBe('normal');
    expect(c.toleranceFor('peer')).toBe(LEVELS.normal);
    expect(LEVELS.normal.lo).toBe(TOLERANCE.lo);
  });

  test('two violations → strict (tighten fast)', () => {
    const c = new EnvelopeController();
    c.observe('peer', slow);
    expect(c.levelFor('peer')).toBe('strict'); // 0.5 ≥ 0.34 — one strike is enough
    c.observe('peer', ok);
    expect(c.levelFor('peer')).toBe('strict'); // 0.45 — still above exit
  });

  test('loosening is ~10× slower — sustained clean history required', () => {
    const c = new EnvelopeController();
    for (let i = 0; i < 13; i++) c.observe('peer', ok);
    expect(c.levelFor('peer')).toBe('normal');   // -0.65 > -0.67, not yet
    c.observe('peer', ok);
    expect(c.levelFor('peer')).toBe('relaxed');  // -0.70 ≤ -0.67
  });

  test('hysteresis — a single clean sample does not relax a strict peer', () => {
    const c = new EnvelopeController();
    c.observe('peer', slow);
    c.observe('peer', slow); // score 1.0
    c.observe('peer', ok);   // 0.95 — well above STRICT_EXIT
    expect(c.levelFor('peer')).toBe('strict');
  });

  test('per-peer isolation — one bad peer moves nobody else', () => {
    const c = new EnvelopeController();
    c.observe('bad', slow);
    c.observe('bad', slow);
    expect(c.levelFor('bad')).toBe('strict');
    expect(c.levelFor('innocent')).toBe('normal');
  });

  test('refusals and failures count, softer than band violations', () => {
    const c = new EnvelopeController();
    c.observe('peer', { refused: 'busy' });
    expect(c.levelFor('peer')).toBe('normal'); // 0.25 < 0.34
    c.observe('peer', { failed: 'bad-result' });
    expect(c.levelFor('peer')).toBe('strict'); // 0.25+0.5 ≥ 0.34
  });

  test('unclassified samples are neutral — no verdict, no move', () => {
    const c = new EnvelopeController();
    c.observe('peer', { band: 'unclassified' });
    expect(c.peers.get('peer').score).toBe(0);
  });
});

describe('EnvelopeController — global floor + bounds', () => {
  test('seal-failure epoch tightens EVERYONE, clean epochs only loosen the floor', () => {
    const c = new EnvelopeController();
    for (let i = 0; i < 14; i++) c.observe('peer', ok);
    expect(c.levelFor('peer')).toBe('relaxed');
    // A forgery wave: global floor rises, effective level follows.
    c.observeEpochHealth(3, 7);
    c.observeEpochHealth(3, 7);
    expect(c.global.level).toBe('strict');
    expect(c.levelFor('peer')).toBe('strict'); // floor beats relaxed
  });

  test('tolerance never exceeds fixed LEVELS', () => {
    const c = new EnvelopeController();
    c.observe('peer', slow); c.observe('peer', slow); c.observe('peer', slow);
    expect(c.toleranceFor('peer')).toBe(LEVELS.strict);
    for (let i = 0; i < 60; i++) c.observe('peer', ok);
    expect(c.toleranceFor('peer')).toBe(LEVELS.relaxed);
  });

  test('envelopeFor honors the controller tolerance — narrower when strict', () => {
    const c = new EnvelopeController();
    c.observe('peer', slow);
    const base = envelopeFor(work, 'ferrous');
    const strict = envelopeFor(work, 'ferrous', c.toleranceFor('peer'));
    expect(strict.minNs).toBeGreaterThan(base.minNs);
    expect(strict.maxNs).toBeLessThan(base.maxNs);
  });
});

describe('EnvelopeController — challenge weighting', () => {
  afterEach(() => vi.restoreAllMocks());

  test('suspicion biases the spot-audit pick', () => {
    const c = new EnvelopeController();
    c.observe('shady', slow);
    expect(c.challengeWeight('shady')).toBe(3);
    expect(c.challengeWeight('clean')).toBe(1);
    for (let i = 0; i < 14; i++) c.observe('vet', ok);
    expect(c.challengeWeight('vet')).toBe(0.5);
  });

  test('pickTarget lands on the strict peer when the roll is high', () => {
    const c = new EnvelopeController();
    c.observe('shady', slow);
    vi.spyOn(Math, 'random').mockReturnValue(0.999);
    // weights: clean 1, shady 3 — total 4; r=3.996 lands on shady.
    expect(c.pickTarget(['clean', 'shady'])).toBe('shady');
    vi.spyOn(Math, 'random').mockReturnValue(0.1);
    expect(c.pickTarget(['clean', 'shady'])).toBe('clean');
    expect(c.pickTarget([])).toBeNull();
  });
});
