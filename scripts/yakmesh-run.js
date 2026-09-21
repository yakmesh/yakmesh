#!/usr/bin/env node
/**
 * yakmesh-run — supervisor + ACT swap consumer
 *
 * Launch the node through this instead of `node server/index.js`:
 *
 *     node scripts/yakmesh-run.js
 *
 * What it does, in a loop:
 *   1. Spawn `node server/index.js` with inherited stdio.
 *   2. On child exit, look for data/act-restart.json. Absent → exit with
 *      the child's code (normal shutdown).
 *   3. Present → if data/pending-update/package.zip is staged, verify it
 *      against data/pending-update/offer.json (SHA-256 written at fetch
 *      time, inside the signed proposal), back up every file it would
 *      overwrite into data/rollback-<ts>/, extract, and overlay onto the
 *      install — excluding data/, node_modules/, .git/, models/.
 *   4. Respawn. If the freshly-swapped child dies within BOOT_GRACE_MS,
 *      restore the rollback and exit non-zero.
 *
 * The swap happens while no node process is running, so locked files and
 * fs-hardening baselining never conflict — FileGuardian baselines the new
 * tree on first post-swap boot.
 *
 * ZIP extraction is a minimal central-directory reader (methods 0 + 8 via
 * zlib.inflateRawSync) — no third-party zip dependency.
 */

import { spawn } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, rmSync, mkdirSync, copyFileSync, readdirSync, statSync, unlinkSync, createWriteStream, fstatSync, openSync, closeSync, chmodSync } from 'node:fs';
import { inflateRawSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DATA = join(ROOT, 'data');
const MARKER = join(DATA, 'act-restart.json');
const STAGING = join(DATA, 'pending-update');
const PKG = join(STAGING, 'package.zip');
const OFFER = join(STAGING, 'offer.json');
const BOOT_GRACE_MS = 60000;

const EXCLUDE_DIRS = new Set(['data', 'node_modules', '.git', 'models']);

// ---------------------------------------------------------------
// Minimal ZIP reader — central directory only (deflate + stored)
// ---------------------------------------------------------------
function* zipEntries(buf) {
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

// ---------------------------------------------------------------
// Swap machinery
// ---------------------------------------------------------------
function* walk(dir, base = dir) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    const rel = relative(base, p).replace(/\\/g, '/');
    const top = rel.split('/')[0];
    if (e.isDirectory()) {
      if (EXCLUDE_DIRS.has(top)) continue;
      yield* walk(p, base);
    } else {
      yield { abs: p, rel };
    }
  }
}

function applyPendingUpdate() {
  const pkg = readFileSync(PKG);
  const sha = createHash('sha256').update(pkg).digest('hex');

  if (existsSync(OFFER)) {
    const offer = JSON.parse(readFileSync(OFFER, 'utf8'));
    if (offer.packageSha256 && offer.packageSha256 !== sha) {
      throw new Error(`staged package sha256 mismatch (got ${sha.slice(0, 16)}…, offer ${offer.packageSha256.slice(0, 16)}…) — refusing swap`);
    }
  }

  const rollbackDir = join(DATA, `rollback-${Date.now()}`);
  const added = [];
  let overlaid = 0;

  for (const { name, data } of zipEntries(pkg)) {
    const rel = name.replace(/\\/g, '/');
    const top = rel.split('/')[0];
    // data/manifest.json is build metadata, not runtime state — it must ride
    // the update or the node boots into a perpetual "upgrade detected" state.
    const isManifest = rel === 'data/manifest.json';
    if ((EXCLUDE_DIRS.has(top) && !isManifest) || rel.endsWith('/')) continue;

    const dest = join(ROOT, rel);
    if (!dest.startsWith(ROOT)) continue; // zip-slip guard

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

  console.log(`[yakmesh-run] update applied: ${overlaid} files, sha256 ${sha.slice(0, 16)}…, rollback → ${relative(ROOT, rollbackDir)}`);
  return { rollbackDir: existsSync(rollbackDir) ? rollbackDir : null };
}

function restoreRollback(rollbackDir) {
  if (!rollbackDir || !existsSync(rollbackDir)) return;
  let restored = 0;
  const addedList = join(rollbackDir, 'added-files.json');
  if (existsSync(addedList)) {
    try {
      for (const rel of JSON.parse(readFileSync(addedList, 'utf8'))) {
        const p = join(ROOT, rel);
        if (p.startsWith(ROOT) && existsSync(p)) unlinkSync(p);
      }
    } catch {}
  }
  for (const { abs, rel } of walk(rollbackDir)) {
    if (rel === 'added-files.json') continue;
    copyFileSync(abs, join(ROOT, rel));
    restored++;
  }
  console.error(`[yakmesh-run] child died after swap — restored ${restored} files from rollback`);
}

// ---------------------------------------------------------------
// Supervisor loop
// ---------------------------------------------------------------
// Tee child output to data/supervisor.log so headless/Windows runs keep a
// durable log (VIEW-YAKMESH-LOG.bat reads this). stdin stays inherited for
// the upgrade Y/N prompt.
let logStream = null;
function getLog() {
  if (!logStream) {
    try { logStream = createWriteStream(join(DATA, 'supervisor.log'), { flags: 'a' }); } catch {}
  }
  return logStream;
}
// When the supervisor is launched with stdout/stderr already redirected to
// data/supervisor.log (`node yakmesh-run.js >> data/supervisor.log 2>&1` —
// the standard nohup/service pattern), writing each child chunk to the
// stream AND the log stream duplicates every line. Detect that case by
// comparing the stream's fd target (dev+ino) with the log file's.
const _fdIsLog = new Map();
function streamIsLogFile(stream) {
  const fd = stream?.fd;
  if (fd == null) return false;
  if (_fdIsLog.get(fd)) return true;
  try {
    const a = fstatSync(fd);
    const t = openSync(join(DATA, 'supervisor.log'), 'r');
    try {
      const b = fstatSync(t);
      if (a.dev === b.dev && a.ino === b.ino) {
        _fdIsLog.set(fd, true);
        return true;
      }
    } finally { closeSync(t); }
  } catch { /* log file may not exist yet — recheck next chunk */ }
  return false;
}
function tee(stream, chunk) {
  try { stream.write(chunk); } catch {}
  const s = getLog();
  if (s && !streamIsLogFile(stream)) s.write(chunk);
}

// ---------------------------------------------------------------
// PQ bridge (attestation) child — optional, managed
// ---------------------------------------------------------------
// The node's attestation path (hourglass sign/verify, yakcoin seals,
// claim verification) talks to yakos-pq-bridge. When a bridge is already
// answering (systemd service, scheduled task, manual start) we adopt it
// and spawn nothing; when nothing answers but a binary sits beside this
// script, we run it ourselves so attestation works out of the box.
//
//   YAKOS_PQ_BRIDGE      bridge URL (default http://127.0.0.1:9995)
//   YAKOS_PQ_BRIDGE_BIN  explicit binary path (overrides auto-detect)
//   YAKMESH_NO_BRIDGE=1  never spawn (bridge managed elsewhere / absent)
const BRIDGE_URL = process.env.YAKOS_PQ_BRIDGE || 'http://127.0.0.1:9995';
let bridgeChild = null;
let bridgeRestarts = 0;
let bridgeBin;           // undefined = unresolved, null = none found
let bridgeWarned = false;

function resolveBridgeBin() {
  if (process.env.YAKOS_PQ_BRIDGE_BIN) return process.env.YAKOS_PQ_BRIDGE_BIN;
  const exe = process.platform === 'win32' ? 'yakos-pq-bridge.exe' : 'yakos-pq-bridge';
  const exact = join(ROOT, exe);
  if (existsSync(exact)) return exact;
  // Dated-deploy convention: yakos-pq-bridge-YYYYMMDD(.exe) — newest wins.
  try {
    const dated = readdirSync(ROOT)
      .filter(f => /^yakos-pq-bridge-\d+(\.exe)?$/.test(f))
      .sort();
    if (dated.length) return join(ROOT, dated[dated.length - 1]);
  } catch { }
  return null;
}

async function bridgeHealthy() {
  try {
    const res = await fetch(`${BRIDGE_URL}/health`, { signal: AbortSignal.timeout(1500) });
    return res.ok;
  } catch { return false; }
}

function spawnBridge() {
  const child = spawn(bridgeBin, [], {
    cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], env: process.env, windowsHide: true,
  });
  bridgeChild = child;
  console.log(`[yakmesh-run] pq-bridge spawned (pid ${child.pid}) — ${bridgeBin}`);
  child.stdout?.on('data', (c) => tee(process.stdout, c));
  child.stderr?.on('data', (c) => tee(process.stderr, c));
  child.on('exit', (code) => {
    if (bridgeChild === child) bridgeChild = null;
    const delay = Math.min(60000, 2000 * 2 ** bridgeRestarts++);
    console.log(`[yakmesh-run] pq-bridge exited (code ${code ?? '?'}) — rechecking in ${delay / 1000}s`);
    setTimeout(ensureBridge, delay);
  });
}

async function ensureBridge() {
  if (process.env.YAKMESH_NO_BRIDGE === '1') return;
  if (bridgeChild) return;                    // ours and still running
  if (await bridgeHealthy()) {
    if (!bridgeWarned) {
      bridgeWarned = true;
      console.log(`[yakmesh-run] pq-bridge reachable at ${BRIDGE_URL} — attestation enabled`);
    }
    return;                                    // external bridge — adopt it
  }
  if (bridgeBin === undefined) bridgeBin = resolveBridgeBin();
  if (!bridgeBin) {
    if (!bridgeWarned) {
      bridgeWarned = true;
      console.log('[yakmesh-run] pq-bridge unreachable and no binary found — attestation idle. ' +
        'Drop yakos-pq-bridge(.exe) beside this script or set YAKOS_PQ_BRIDGE_BIN.');
    }
    return;
  }
  spawnBridge();
}

// Bridge lifecycle is independent of the node child — it survives ACT
// swaps (the package never contains it) and dies with the supervisor.
// The node child dies with us too: an orphaned node keeps the WS port
// bound and fights the respawn.
let nodeChild = null;
function killChildren() {
  try { bridgeChild?.kill(); } catch { }
  try { nodeChild?.kill(); } catch { }
}
process.on('exit', killChildren);
// 'exit' does NOT fire on signals — without these, kill/Ctrl+C orphans
// the node child (it keeps the WS port bound and fights the respawn).
for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(sig, () => { killChildren(); process.exit(128 + (sig === 'SIGINT' ? 2 : sig === 'SIGHUP' ? 1 : 15)); });
}
ensureBridge().catch(() => { });
const _bridgeTimer = setInterval(() => ensureBridge().catch(() => { }), 30_000);
_bridgeTimer.unref?.();

function run() {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [join(ROOT, 'server', 'index.js'), ...process.argv.slice(2)], {
      cwd: ROOT,
      stdio: ['inherit', 'pipe', 'pipe'],
      env: process.env,
    });
    nodeChild = child;
    child.stdout?.on('data', (c) => tee(process.stdout, c));
    child.stderr?.on('data', (c) => tee(process.stderr, c));
    child.on('exit', (code) => { if (nodeChild === child) nodeChild = null; resolve(code ?? 1); });
  });
}

let lastRollback = null;
let swapAt = 0;

// A marker present at supervisor start means the previous transition was
// interrupted (supervisor died with its child, or machine rebooted
// mid-swap). Apply the staged package before the first spawn.
if (existsSync(MARKER) && existsSync(PKG)) {
  console.log('[yakmesh-run] pending transition found at startup — applying staged update first');
  try { lastRollback = applyPendingUpdate().rollbackDir; swapAt = Date.now(); rmSync(MARKER, { force: true }); rmSync(STAGING, { recursive: true, force: true }); }
  catch (err) { console.error(`[yakmesh-run] startup swap failed: ${err.message}`); rmSync(MARKER, { force: true }); }
}

for (;;) {
  const startedAt = Date.now();
  const code = await run();

  // A child that dies inside the post-swap grace window means the new
  // code is broken — restore the rollback BEFORE the no-marker exit
  // (marker+staging are already consumed by then; this check must not
  // depend on them).
  if (lastRollback && Date.now() - swapAt < BOOT_GRACE_MS) {
    console.error('[yakmesh-run] child died within grace of swap — restoring rollback');
    restoreRollback(lastRollback);
    rmSync(MARKER, { force: true });
    rmSync(STAGING, { recursive: true, force: true });
    process.exit(1);
  }

  if (!existsSync(MARKER)) process.exit(code);

  // ACT restart. Apply staged package if present.
  let marker = {};
  try { marker = JSON.parse(readFileSync(MARKER, 'utf8')); } catch { }
  console.log(`[yakmesh-run] ACT restart marker found (epoch ${marker.targetEpoch ?? '?'})`);

  if (existsSync(PKG)) {
    try {
      // A swap whose child died inside the grace window → restore + bail.
      if (lastRollback && Date.now() - swapAt < BOOT_GRACE_MS) {
        restoreRollback(lastRollback);
        rmSync(MARKER, { force: true });
        rmSync(STAGING, { recursive: true, force: true });
        process.exit(1);
      }
      lastRollback = applyPendingUpdate().rollbackDir;
      swapAt = Date.now();
      rmSync(STAGING, { recursive: true, force: true });
    } catch (err) {
      console.error(`[yakmesh-run] update apply failed: ${err.message}`);
      rmSync(MARKER, { force: true });
      process.exit(1);
    }
  }

  rmSync(MARKER, { force: true });
  console.log('[yakmesh-run] respawning node…');
}
