#!/usr/bin/env node
/**
 * iO Mnemonic File Manifest Generator
 *
 * Run at build time to capture the oracle's file list and encode it
 * as a QUANTUM_WORDLIST mnemonic manifest.  The oracle decodes this
 * at startup and warns if files are missing or unexpected files appear.
 *
 * Usage:
 *   node generate-manifest.js [--root <path>]  (default: parent dir)
 *
 * Output:
 *   Writes deploy-packages/manifest.json with { files, hash, mnemonic }
 */

import { randomBytes } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { readdirSync, readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Mirror the QUANTUM_WORDLIST from network-identity.js (must stay in sync)
const QUANTUM_WORDLIST = JSON.parse(
    readFileSync(join(__dirname, 'wordlist-snapshot.json'), 'utf-8')
).words;

if (QUANTUM_WORDLIST.length !== 256) {
    throw new Error(`Wordlist must have exactly 256 words, got ${QUANTUM_WORDLIST.length}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// File walk — must mirror oracle/validation-oracle-hardened.js EXACTLY
// ─────────────────────────────────────────────────────────────────────────────

const EXCLUDE_DIRS = [
    'node_modules', '.git', '.github', 'data', 'database', 'logs', 'models',
    '.vscode', 'coverage', 'dist', 'build', 'tests', 'test-nodes',
    'deploy-packages', 'deploy', 'scripts', 'docs', 'website', 'marketing',
    'announcements', 'assets', 'types', 'shortcuts', 'memory-bank', 'yakbot',
    'hostinger', 'cli', 'dashboard', 'templates', 'examples',
];

const SOURCE_EXTENSIONS = ['.js', '.mjs', '.cjs', '.json', '.ts', '.tsx'];

const EXCLUDE_FILES = [
    'package-lock.json', '.env', '.env.local', 'vitest.config.js',
    'knowledge-base.js', 'update-docs-nav.cjs', 'convert-tests.cjs',
];

const EXCLUDE_PREFIXES = ['test-', 'audit-', 'verify-'];

function walkDirectory(dir, results, baseDir) {
    if (!baseDir) baseDir = dir;
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); }
    catch { return; }

    for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        const relativePath = fullPath
            .replace(baseDir, '')
            .replace(/^[/\\]/, '')
            .replace(/\\/g, '/');

        if (entry.isDirectory()) {
            if (EXCLUDE_DIRS.includes(entry.name)) continue;
            if (entry.name.startsWith('data-') || entry.name.startsWith('data_')) continue;
            walkDirectory(fullPath, results, baseDir);
        } else if (entry.isFile()) {
            if (EXCLUDE_FILES.includes(entry.name)) continue;
            if (/\.(test|spec)\.(js|mjs|cjs)$/.test(entry.name)) continue;
            if (EXCLUDE_PREFIXES.some(p => entry.name.startsWith(p))) continue;
            const ext = entry.name.slice(entry.name.lastIndexOf('.'));
            if (!SOURCE_EXTENSIONS.includes(ext)) continue;
            results.push(relativePath);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mnemonic encoding: file path → 2-word mnemonic
// ─────────────────────────────────────────────────────────────────────────────

function pathToMnemonic(filePath) {
    const hash = sha3_256(utf8ToBytes(filePath));
    // Use first 2 bytes as word indices
    return `${QUANTUM_WORDLIST[hash[0]]}-${QUANTUM_WORDLIST[hash[1]]}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

const rootArg = process.argv.indexOf('--root');
const rootDir = rootArg >= 0 ? process.argv[rootArg + 1] : join(__dirname, '..');

console.log(`iO Manifest: scanning ${rootDir}`);

const files = [];
walkDirectory(rootDir, files);
files.sort((a, b) => a.localeCompare(b));

// Compute content hash (same as oracle)
const contentParts = [];
for (const f of files) {
    try {
        const content = readFileSync(join(rootDir, f), 'utf-8');
        contentParts.push(`=== ${f} ===\n${content}`);
    } catch (err) {
        contentParts.push(`=== ${f} ===\nERROR: ${err.message}`);
    }
}
const codebaseHash = bytesToHex(sha3_256(utf8ToBytes(contentParts.join('\n'))));

// Build mnemonic manifest
const mnemonics = files.map(f => ({
    path: f,
    mnemonic: pathToMnemonic(f),
}));

const manifest = {
    version: 1,
    generatedAt: new Date().toISOString(),
    codebaseHash: codebaseHash.slice(0, 16) + '...',
    buildNonce: bytesToHex(randomBytes(32)),
    fileCount: files.length,
    files,
    mnemonics,
};

const outDir = join(rootDir, 'data');
if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
const outPath = join(outDir, 'manifest.json');
writeFileSync(outPath, JSON.stringify(manifest, null, 2));
console.log(`iO Manifest: ${files.length} files → data/manifest.json`);
console.log(`iO Manifest: hash = ${codebaseHash.slice(0, 16)}...`);
