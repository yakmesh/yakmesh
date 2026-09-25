#!/usr/bin/env node
/**
 * stage-dist.mjs — Stage a dist package containing EXACTLY the manifest file set.
 *
 * Why this exists: hand-assembled staging dirs accumulate stale files. A stray
 * hashed-extension file (.js/.json/...) in a hashed dir is flagged "unexpected"
 * by the oracle, quarantined at runtime, and the file set changes → codebase
 * hash drifts → INCOMPATIBLE_CODEBASE between nodes running "the same" zip.
 *
 * This script copies ONLY manifest.files from the repo, plus oracle-invisible
 * extras (package-lock.json, *.bat, *.md, data/manifest.json), then runs
 * generate-manifest.js against the staged tree to prove the hash is identical.
 *
 * Usage: node scripts/stage-dist.mjs <outDir>
 */

import { readFileSync, readdirSync, mkdirSync, copyFileSync, cpSync, existsSync, rmSync, chmodSync } from 'fs';
import { join, dirname } from 'path';
import { execFileSync } from 'child_process';

const repo = join(import.meta.dirname, '..');
const out = process.argv[2];
if (!out) {
    console.error('usage: node scripts/stage-dist.mjs <outDir>');
    process.exit(1);
}

const manifest = JSON.parse(readFileSync(join(repo, 'data', 'manifest.json'), 'utf8'));

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

for (const f of manifest.files) {
    const dst = join(out, f);
    mkdirSync(dirname(dst), { recursive: true });
    copyFileSync(join(repo, f), dst);
    // copyFileSync preserves the source mode — NTFS-mounted source files
    // are read-only (r-x), which makes the later asset-dir cpSync fail
    // with EACCES when overwriting them. Force writable.
    chmodSync(dst, 0o644);
}

// Runtime asset dirs: contain unhashed files the node needs (web UI, schemas,
// docs). Hashed files inside them are already covered by manifest.files; any
// stray hashed file would be caught by the self-verify below.
const ASSET_DIRS = ['dashboard', 'public', 'htdocs', 'templates', 'database', 'content', 'embedded-docs', 'models'];
for (const dir of ASSET_DIRS) {
    const src = join(repo, dir);
    if (existsSync(src)) cpSync(src, join(out, dir), { recursive: true });
}

// Oracle-invisible extras: not SOURCE_EXTENSIONS, or in EXCLUDE_FILES/EXCLUDE_DIRS
for (const extra of ['package-lock.json', 'start-yakmesh.bat', 'start-yakmesh-silent.vbs', 'VIEW-YAKMESH-LOG.bat', 'STOP-YAKMESH.bat', 'README.md', 'LICENSE', 'CHANGELOG.md', 'utils/wintun.dll', 'utils/dna-spiral.wasm', 'utils/verify-worker.js', 'scripts/yakmesh-run.js', 'tools/npu-prover/START-PROVER.bat', 'tools/npu-prover/xrt/yak_xrt_shim.dll', 'tools/npu-prover/xrt/final.xclbin', 'tools/npu-prover/xrt/insts.bin']) {
    if (existsSync(join(repo, extra))) {
        mkdirSync(dirname(join(out, extra)), { recursive: true });
        copyFileSync(join(repo, extra), join(out, extra));
    }
}

// Attestation bundle — INTEGRAL to every package, not an optional extra.
// yakmesh-run.js resolves yakos-pq-bridge[.exe] (exact name or dated
// -YYYYMMDD) at the package root; the launcher provisions the hardware-bound
// keystore via yakos-keystore[.exe]. The binaries live at the repo root as
// untracked build artifacts (gitignored, oracle-invisible — .exe is not a
// SOURCE_EXTENSION) and ride every staged dist. A package without them is a
// package that cannot attest — that is a broken package, not a lite one.
// Set YAKMESH_STAGE_NO_ATTEST=1 only for intentionally bridge-less builds.
const attBins = readdirSync(repo)
    .filter(f => /^yakos-(pq-bridge|keystore)(-\d+)?(\.exe)?$/.test(f));
for (const f of attBins) {
    copyFileSync(join(repo, f), join(out, f));
}
const haveBridge = attBins.some(f => f.startsWith('yakos-pq-bridge'));
const haveKeystore = attBins.some(f => f.startsWith('yakos-keystore'));
if ((!haveBridge || !haveKeystore) && process.env.YAKMESH_STAGE_NO_ATTEST !== '1') {
    console.error('stage-dist: attestation bundle incomplete at repo root ' +
        `(pq-bridge=${haveBridge ? 'yes' : 'MISSING'}, keystore=${haveKeystore ? 'yes' : 'MISSING'}). ` +
        'Build/drop the binaries at the repo root, or set YAKMESH_STAGE_NO_ATTEST=1 ' +
        'for a deliberately bridge-less package.');
    process.exit(1);
}
if (attBins.length) console.log(`stage-dist: attestation bundle → ${attBins.join(', ')}`);

mkdirSync(join(out, 'data'), { recursive: true });
copyFileSync(join(repo, 'data', 'manifest.json'), join(out, 'data', 'manifest.json'));

// Self-verify: hash the staged tree — must equal the repo manifest hash.
const output = execFileSync(
    process.execPath,
    [join(repo, 'deploy-packages', 'generate-manifest.js'), '--root', out],
    { encoding: 'utf8' }
);
const staged = JSON.parse(readFileSync(join(out, 'data', 'manifest.json'), 'utf8'));

if (staged.fullCodebaseHash !== manifest.fullCodebaseHash) {
    console.error(`STAGE HASH MISMATCH: repo=${manifest.fullCodebaseHash.slice(0, 16)} staged=${staged.fullCodebaseHash.slice(0, 16)}`);
    process.exit(1);
}

console.log(output.trim());
console.log(`stage-dist: ${manifest.files.length} files verified, hash ${staged.fullCodebaseHash.slice(0, 16)} → ${out}`);
