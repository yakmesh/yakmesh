/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 */

/**
 * Upgrade-grace tests — when the loaded manifest describes a PREVIOUS
 * tree (ACT upgrade detected: manifest hash ≠ oracle selfHash), files
 * absent from it are new code, not tampering. handleStaleFiles must
 * hold them for review without touching the filesystem; without the
 * flag the normal quarantine path must still work.
 *
 * @module security/tests/upgrade-grace.test
 */

import { describe, test, expect, afterAll } from 'vitest';
import { writeFileSync, existsSync, rmSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { ValidationOracle } from '../../oracle/validation-oracle-hardened.js';

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const probe = 'oracle/__upgrade_grace_probe__.js';
const probePath = join(rootDir, probe);
const quarantineProbe = join(rootDir, 'data', 'quarantine', 'oracle', '__upgrade_grace_probe__.js');

afterAll(() => {
  rmSync(probePath, { force: true });
  rmSync(quarantineProbe, { force: true });
});

describe('handleStaleFiles upgrade grace', () => {
  test('grace mode holds files without touching the filesystem', () => {
    writeFileSync(probePath, '// probe\n');
    const oracle = new ValidationOracle();
    const r = oracle.handleStaleFiles([probe], { grace: true });
    expect(r.mode).toBe('grace');
    expect(r.handled).toBe(0);
    expect(r.held).toEqual([probe]);
    expect(r.errors).toEqual([]);
    expect(existsSync(probePath)).toBe(true);
    expect(existsSync(quarantineProbe)).toBe(false);
  });

  test('non-grace mode still quarantines for real', () => {
    writeFileSync(probePath, '// probe\n');
    const oracle = new ValidationOracle();
    const r = oracle.handleStaleFiles([probe]);
    expect(r.mode).toBe('quarantine');
    expect(r.handled).toBe(1);
    expect(existsSync(probePath)).toBe(false);
    expect(existsSync(quarantineProbe)).toBe(true);
  });

  test('empty input is a no-op regardless of grace', () => {
    const oracle = new ValidationOracle();
    expect(oracle.handleStaleFiles([], { grace: true })).toEqual(
      { handled: 0, mode: 'none', errors: [] });
    expect(oracle.handleStaleFiles(null)).toEqual(
      { handled: 0, mode: 'none', errors: [] });
  });
});
