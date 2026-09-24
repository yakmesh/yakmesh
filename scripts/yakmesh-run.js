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

import { spawn, execSync } from 'node:child_process';
import { zipEntries, applyUpgradePackage, restoreRollback } from '../utils/in-place-upgrade.js';
import { existsSync, readFileSync, writeFileSync, rmSync, mkdirSync, copyFileSync, readdirSync, statSync, unlinkSync, renameSync, createWriteStream, fstatSync, openSync, closeSync, chmodSync } from 'node:fs';
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

// onnxruntime-node's CUDA EP needs CUDA-13 runtime libs (libcublasLt.so.13
// etc.), which often live outside the default linker path — pip-bundled
// nvidia wheels, /usr/local/cuda-*, etc. If ldconfig can't resolve them,
// find a directory that has them and prepend it to LD_LIBRARY_PATH so the
// spawned node (and bridge) can actually load the CUDA provider instead of
// silently falling back to CPU.
function cudaLibPathFix() {
  if (process.platform !== 'linux') return;
  try {
    const ld = execSync('ldconfig -p', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    if (ld.includes('libcublasLt.so.13')) return;
  } catch { }
  const dirs = [];
  const add = d => { try { if (existsSync(join(d, 'libcublasLt.so.13'))) dirs.push(d); } catch { } };
  add('/usr/local/cuda/lib64');
  add('/opt/cuda/lib64');
  try { for (const e of readdirSync('/usr/local')) if (e.startsWith('cuda')) add(join('/usr/local', e, 'lib64')); } catch { }
  try {
    const out = execSync(
      "find /home /root /opt -maxdepth 10 -type d -path '*/nvidia/cu13/lib' 2>/dev/null | head -4",
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 15000 });
    for (const d of out.split('\n').filter(Boolean)) add(d);
  } catch { }
  if (!dirs.length) return;
  process.env.LD_LIBRARY_PATH = [...dirs, process.env.LD_LIBRARY_PATH].filter(Boolean).join(':');
  console.log(`[yakmesh-run] CUDA 13 libs not on linker path — prepended ${dirs.join(', ')} to LD_LIBRARY_PATH`);
}
cudaLibPathFix();

// ---------------------------------------------------------------
// Swap machinery — shared with `yakmesh upgrade` (utils/in-place-upgrade.js)
// ---------------------------------------------------------------
function applyPendingUpdate() {
  const pkg = readFileSync(PKG);
  const sha = createHash('sha256').update(pkg).digest('hex');

  if (existsSync(OFFER)) {
    const offer = JSON.parse(readFileSync(OFFER, 'utf8'));
    if (offer.packageSha256 && offer.packageSha256 !== sha) {
      throw new Error(`staged package sha256 mismatch (got ${sha.slice(0, 16)}…, offer ${offer.packageSha256.slice(0, 16)}…) — refusing swap`);
    }
  }

  const { overlaid, quarantined, rollbackDir } = applyUpgradePackage(
    zipEntries(pkg),
    { root: ROOT, dataDir: DATA, log: (m) => console.log(`[yakmesh-run] ${m}`) });
  console.log(`[yakmesh-run] update applied: ${overlaid} files${quarantined ? `, ${quarantined} leftover(s) quarantined` : ''}, sha256 ${sha.slice(0, 16)}…, rollback → ${rollbackDir ? relative(ROOT, rollbackDir) : 'none'}`);
  return { rollbackDir };
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
    try {
      mkdirSync(DATA, { recursive: true });
      logStream = createWriteStream(join(DATA, 'supervisor.log'), { flags: 'a' });
      // ENOENT/EACCES surface as an async 'error' event, not a throw —
      // an unhandled error event would crash the supervisor.
      logStream.on('error', () => { logStream = null; });
    } catch { }
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
      // Marker so the node (and CLI/dashboard) can tell a supervised run —
      // staged update swaps only complete under this supervisor.
      env: { ...process.env, YAKMESH_SUPERVISED: '1' },
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
    restoreRollback(lastRollback, ROOT);
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
        restoreRollback(lastRollback, ROOT);
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
