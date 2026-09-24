/**
 * In-place package upgrade engine — shared by:
 *   - scripts/yakmesh-run.js  (ACT self-update: peer-offered package staged
 *     to data/pending-update, applied at supervisor start)
 *   - cli/index.js `yakmesh upgrade` (manual upgrade: user points at a
 *     downloaded package and applies it in place)
 *
 * Semantics (both paths MUST stay identical):
 *   - Files in the package overlay the install root. EXCLUDE_DIRS are never
 *     touched — data/, node_modules/, .git/, models/ survive the upgrade,
 *     which is exactly what preserves identity + personal setup.
 *   - data/manifest.json is the exception: it is build metadata and must
 *     ride the update or the node boots into perpetual "upgrade detected".
 *   - Every overwritten file is backed up to data/rollback-<ts>; files the
 *     package ADDED are listed so rollback can remove them.
 *   - After the overlay, leftovers (files deleted between versions) are
 *     quarantined per the new manifest — the oracle hashes every source
 *     file into the network fingerprint, so a leftover .js silently forks
 *     the node onto a different network.
 */

import { existsSync, readFileSync, writeFileSync, rmSync, mkdirSync, copyFileSync, readdirSync, unlinkSync, renameSync, chmodSync } from 'node:fs';
import { inflateRawSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { join, dirname, relative } from 'node:path';

export const EXCLUDE_DIRS = new Set(['data', 'node_modules', '.git', 'models']);

const HASH_EXTS = new Set(['.js', '.mjs', '.cjs', '.json', '.ts', '.tsx']);
const HASH_EXCLUDE_DIRS = new Set([
  'node_modules', '.git', '.github', 'data', 'database', 'logs', 'models',
  '.vscode', 'coverage', 'dist', 'build', 'tests', 'test-nodes',
  'deploy-packages', 'deploy', 'scripts', 'docs', 'website', 'marketing',
  'announcements', 'assets', 'types', 'shortcuts', 'memory-bank', 'yakbot',
  'hostinger', 'cli', 'dashboard', 'templates', 'examples',
]);
const HASH_EXCLUDE_FILES = new Set([
  'package-lock.json', '.env', '.env.local', 'vitest.config.js',
  'knowledge-base.js', 'update-docs-nav.cjs', 'convert-tests.cjs',
]);
const HASH_EXCLUDE_PREFIXES = ['test-', 'audit-', 'verify-'];

/**
 * Minimal ZIP reader — central directory only (deflate + stored).
 * Yields {name, data} for each entry.
 */
export function* zipEntries(buf) {
  // End Of Central Directory record
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0 && i >= buf.length - 66000; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('not a zip file (no EOCD)');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);

  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('bad central dir entry');
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOff = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');

    // Local header: name/extra lengths can differ — re-read them
    const lNameLen = buf.readUInt16LE(localOff + 26);
    const lExtraLen = buf.readUInt16LE(localOff + 28);
    const dataOff = localOff + 30 + lNameLen + lExtraLen;
    const comp = buf.subarray(dataOff, dataOff + compSize);

    let data;
    if (method === 0) data = Buffer.from(comp);
    else if (method === 8) data = inflateRawSync(comp);
    else throw new Error(`unsupported zip method ${method} for ${name}`);

    yield { name, data };
    p += 46 + nameLen + extraLen + commentLen;
  }
}

export function* walk(dir, base = dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    const rel = relative(base, p).replace(/\\/g, '/');
    if (e.isDirectory()) {
      if (EXCLUDE_DIRS.has(rel.split('/')[0])) continue;
      yield* walk(p, base);
    } else {
      yield { abs: p, rel };
    }
  }
}

// Leftover quarantine — files deleted between versions must not survive
// the swap. The oracle hashes every source file on disk into the network
// fingerprint, so one leftover .js silently forks the node onto a
// different network (observed live: archive/security/tls-binding.js).
// The package's data/manifest.json declares the exact hashed set;
// matching disk to that set makes the fingerprint deterministic.
// Scan rules mirror oracle/validation-oracle-hardened.js #walkDirectory —
// keep in sync or quarantine and fingerprint will diverge.
export function* hashableFiles(dir, base = dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    const rel = relative(base, p).replace(/\\/g, '/');
    if (e.isDirectory()) {
      if (HASH_EXCLUDE_DIRS.has(e.name)) continue;
      if (e.name.startsWith('data-') || e.name.startsWith('data_')) continue;
      yield* hashableFiles(p, base);
    } else {
      if (HASH_EXCLUDE_FILES.has(e.name)) continue;
      if (HASH_EXCLUDE_PREFIXES.some(x => e.name.startsWith(x))) continue;
      if (/\.(test|spec)\.(js|mjs|cjs)$/.test(e.name)) continue;
      const ext = e.name.slice(e.name.lastIndexOf('.'));
      if (!HASH_EXTS.has(ext)) continue;
      yield { abs: p, rel };
    }
  }
}

function quarantineLeftovers(root, dataDir, rollbackDir, log) {
  // Canonical hashed set: the new package's manifest file list.
  let canonical = null;
  try {
    const m = JSON.parse(readFileSync(join(dataDir, 'manifest.json'), 'utf8'));
    if (Array.isArray(m?.files)) {
      canonical = new Set(m.files.map(f => String(f).replace(/\\/g, '/')));
    }
  } catch { }
  if (!canonical) {
    log('no manifest file list — leftover quarantine skipped');
    return 0;
  }

  const qdir = join(dataDir, `update-quarantine-${Date.now()}`);
  const moved = [];
  for (const { abs, rel } of hashableFiles(root)) {
    if (canonical.has(rel)) continue;
    const dest = join(qdir, rel);
    mkdirSync(dirname(dest), { recursive: true });
    try { chmodSync(abs, 0o644); } catch { } // FileGuardian may hold it read-only
    renameSync(abs, dest);
    moved.push(rel);
    log(`quarantined leftover ${rel}`);
  }
  // Record for rollback: a failed child restores quarantined files too.
  if (moved.length && rollbackDir && existsSync(rollbackDir)) {
    writeFileSync(join(rollbackDir, 'quarantined-files.json'),
      JSON.stringify({ qdir, files: moved }));
  }
  return moved.length;
}

/**
 * Apply an upgrade package in place.
 *
 * @param {Iterable<{name:string,data:Buffer}>} entries — package files
 *   ({name, data} pairs; zipEntries() output, or walked from an extracted dir)
 * @param {object} opts
 * @param {string} opts.root — install root being upgraded
 * @param {string} opts.dataDir — data dir (rollback + quarantine live here)
 * @param {(msg:string)=>void} [opts.log]
 * @returns {{overlaid:number, added:string[], quarantined:number,
 *            rollbackDir:string|null, sha256:string|null}}
 */
export function applyUpgradePackage(entries, { root, dataDir, log = () => {} }) {
  const rollbackDir = join(dataDir, `rollback-${Date.now()}`);
  const added = [];
  let overlaid = 0;
  let sha = null;

  for (const { name, data } of entries) {
    const rel = name.replace(/\\/g, '/');
    const top = rel.split('/')[0];
    // data/manifest.json is build metadata, not runtime state — it must ride
    // the update or the node boots into a perpetual "upgrade detected" state.
    const isManifest = rel === 'data/manifest.json';
    if ((EXCLUDE_DIRS.has(top) && !isManifest) || rel.endsWith('/')) continue;

    const dest = join(root, rel);
    if (!dest.startsWith(root)) continue; // zip-slip guard

    if (existsSync(dest)) {
      const rb = join(rollbackDir, rel);
      mkdirSync(dirname(rb), { recursive: true });
      copyFileSync(dest, rb);
    } else {
      added.push(rel);
    }
    mkdirSync(dirname(dest), { recursive: true });
    // FileGuardian re-baselines runtime files to read-only — unlock the
    // target before overwrite or the whole swap dies with EACCES.
    try { chmodSync(dest, 0o644); } catch { }
    writeFileSync(dest, data);
    overlaid++;
  }

  // Track files the update ADDED so rollback can remove them — restoring
  // backups alone leaves new files behind and silently poisons the hash.
  if (added.length && existsSync(rollbackDir)) {
    writeFileSync(join(rollbackDir, 'added-files.json'), JSON.stringify(added));
  }

  const quarantined = quarantineLeftovers(root, dataDir, rollbackDir, log);
  return {
    overlaid,
    added,
    quarantined,
    rollbackDir: existsSync(rollbackDir) ? rollbackDir : null,
    sha256: sha,
  };
}

/**
 * Restore a rollback directory produced by applyUpgradePackage.
 * Removes files the update added, un-quarantines leftovers, restores
 * overwritten files from backup.
 */
export function restoreRollback(rollbackDir, root, log = console.error) {
  if (!rollbackDir || !existsSync(rollbackDir)) return;
  const addedList = join(rollbackDir, 'added-files.json');
  if (existsSync(addedList)) {
    try {
      for (const rel of JSON.parse(readFileSync(addedList, 'utf8'))) {
        const p = join(root, rel);
        if (p.startsWith(root) && existsSync(p)) unlinkSync(p);
      }
    } catch { }
  }
  const qList = join(rollbackDir, 'quarantined-files.json');
  if (existsSync(qList)) {
    try {
      const { qdir, files } = JSON.parse(readFileSync(qList, 'utf8'));
      for (const rel of files) {
        const src = join(qdir, rel);
        const dst = join(root, rel);
        if (dst.startsWith(root) && existsSync(src)) {
          mkdirSync(dirname(dst), { recursive: true });
          renameSync(src, dst);
        }
      }
    } catch { }
  }
  let restored = 0;
  for (const { abs, rel } of walk(rollbackDir)) {
    if (rel === 'added-files.json') continue;
    copyFileSync(abs, join(root, rel));
    restored++;
  }
  log(`restored ${restored} files from rollback`);
}
