#!/usr/bin/env node
/**
 * YAKMESH Documentation Sync Workflow
 *
 * One command to sync both website variations:
 *   1. Update navigation in website/docs/*.html (sidebar, journey cards, footer)
 *   2. Build embedded docs bundle (ships with every yakmesh node)
 *   3. Build public web root (dashboard + assets + C2C art + YakAI portraits)
 *
 * Usage:
 *   npm run sync:docs
 *
 * Prerequisites:
 *   - Must be run from yakmesh-node/ directory
 *   - website/ directory must exist at ../website/ (sibling to yakmesh-node/)
 */

import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');
const websiteDir = join(rootDir, '..', 'website');

const steps = [];
const errors = [];

function run(label, cmd, cwd = rootDir) {
  process.stdout.write(`  ${label} ... `);
  try {
    execSync(cmd, { cwd, stdio: 'pipe', encoding: 'utf-8' });
    console.log('done');
    steps.push({ label, status: 'ok' });
  } catch (e) {
    console.log('failed');
    errors.push({ label, error: e.stderr?.toString() || e.message });
    steps.push({ label, status: 'fail' });
  }
}

console.log('\n📚 YAKMESH Documentation Sync');
console.log('================================\n');

// Step 1: Update navigation in website docs
if (process.platform === 'win32') {
  run('Update docs navigation', 'node scripts\\update-docs-nav.cjs', websiteDir);
} else {
  run('Update docs navigation', 'node scripts/update-docs-nav.cjs', websiteDir);
}

// Step 2: Build embedded docs bundle
run('Build embedded docs bundle', 'npm run build:docs');

// Step 3: Build public web root
run('Build public web root', 'npm run build:public');

// Summary
console.log('\n================================');
const ok = steps.filter(s => s.status === 'ok').length;
const fail = steps.filter(s => s.status === 'fail').length;
console.log(`  ${ok}/${steps.length} steps completed`);

if (fail > 0) {
  console.log(`  ${fail} step(s) failed:`);
  for (const e of errors) {
    console.log(`    ✗ ${e.label}`);
    if (e.error) console.log(`      ${e.error.split('\n')[0]}`);
  }
  process.exit(1);
}

console.log('\n  Both website variations are now in sync:');
console.log('    • yakmesh.dev (Hostinger) → ../website/docs/ updated');
console.log('    • Embedded docs (yakmesh-node) → embedded-docs/bundle.js rebuilt');
console.log('    • Public web root → public/ assembled');
console.log('\n  Next: commit changes in both repos:');
console.log('    cd ../Yakmesh && git add website/docs/ && git commit');
console.log('    cd yakmesh-node && git add -A && git commit');
console.log('================================\n');
