/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 */

/**
 * SEVA TIVRA-block tests — capability ads carry an honest accel.HW
 * snapshot so dispatch can see ISA/accelerator differences that
 * {accelerated, npuTops} alone cannot express.
 *
 * @module mesh/tests/seva.test
 */

import { describe, test, expect } from 'vitest';
import { SevaMeshHandler, SEVA_CONFIG } from '../seva.js';

const net = () => ({
  sent: [],
  broadcast(m) { this.sent.push(m); },
  sendTo(id, m) { this.sent.push({ to: id, ...m }); },
});

const TIVRA = {
  cpu: {
    model: 'Ryzen',
    isa: { shaNI: true, avx512: true, vaes: true, gfni: true },
    nativeSha3: true, nativePQ: 'liboqs',
  },
  gpu: { cuda: false, name: null, tensorTops: 0, amd: false },
  onnx: { runtime: true, providers: ['cpu'] },
  npu: { xdna: true, gen: 'xdna1', tops: 16 },
  mkc: { kernels: ['sha3', 'avoth', 'aes'], tiles: 16, crystalRoles: null },
  totalTops: 16,
};

const handler = (over = {}) => new SevaMeshHandler({
  identity: { nodeId: 'us' },
  network: net(),
  enabled: true,
  hardware: { npu: true, npuTops: 16 },
  tivra: TIVRA,
  ...over,
});

describe('SEVA TIVRA capability block', () => {
  test('capability ad carries the tivra snapshot', () => {
    const h = handler();
    h._broadcastCapability();
    const ad = h.network.sent[0];
    expect(ad.type).toBe(SEVA_CONFIG.messageTypes.CAPABILITY);
    expect(ad.tivra).toEqual(TIVRA);
  });

  test('no tivra → field omitted (honest absence, not fabricated)', () => {
    const h = handler({ tivra: undefined });
    h._broadcastCapability();
    expect(h.network.sent[0].tivra).toBeUndefined();
  });

  test('incoming ads store tivra on the peer record', () => {
    const h = handler({ enabled: false });
    h._handleCapability({
      slots: [{ id: 'avoth-hash' }],
      capacity: { accelerated: true },
      avoth: true, providers: ['avoth-triad'], tivra: TIVRA,
    }, 'peerA');
    expect(h.peerCapabilities.get('peerA').tivra).toEqual(TIVRA);
  });

  test('old peers without tivra still register (wire-compatible)', () => {
    const h = handler({ enabled: false });
    h._handleCapability({
      slots: [{ id: 'avoth-hash' }], capacity: {},
    }, 'oldPeer');
    const cap = h.peerCapabilities.get('oldPeer');
    expect(cap).toBeTruthy();
    expect(cap.tivra).toBeNull();
  });

  test('dispatch prefers SHA-NI/native-sha3 peer for avoth slots', () => {
    const h = handler({ enabled: false });
    const base = {
      slots: [{ id: 'avoth-hash' }],
      capacity: { accelerated: true, currentLoad: 0, maxConcurrent: 10 },
      avoth: true, providers: ['avoth-triad'],
    };
    const noMkc = { ...TIVRA, mkc: null };
    h._handleCapability({ ...base, tivra: noMkc }, 'fast');
    h._handleCapability({ ...base }, 'plain');
    expect(h._findBestPeer('avoth-hash')).toBe('fast');
  });

  test('dispatch prefers the MKC kernel path for avoth slots', () => {
    const h = handler({ enabled: false });
    const base = {
      slots: [{ id: 'avoth-hash' }],
      capacity: { accelerated: true, currentLoad: 0, maxConcurrent: 10 },
      avoth: true, providers: ['avoth-triad', 'xrt-iron'],
    };
    const noSilicon = { ...TIVRA, mkc: null, cpu: { ...TIVRA.cpu, isa: {}, nativeSha3: false } };
    h._handleCapability({ ...base, tivra: TIVRA }, 'silicon');
    h._handleCapability({ ...base, tivra: noSilicon }, 'plain');
    expect(h._findBestPeer('avoth-hash')).toBe('silicon');
  });

  test('tivra surfaces in getStats', () => {
    expect(handler().getStats().tivra).toEqual(TIVRA);
  });
});
