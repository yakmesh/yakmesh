#!/usr/bin/env node

/**
 * YAKMESH Public Web Root Builder
 * 
 * Assembles the unified public/ directory from source locations:
 *   - dashboard/index.html  → public/dashboard/
 *   - assets/               → public/assets/  (logos)
 *   - ../c2c/client/public/assets/  → public/c2c/assets/  (game art)
 *   - ../yakai/client/public/*.png  → public/yakai/       (portraits)
 * 
 * The first two are git-tracked. The last two are build artifacts
 * copied from sibling projects (gitignored in public/).
 * 
 * Run: npm run build:public
 * 
 * @author YAKMESH Team
 * @license MIT
 */

import { existsSync, mkdirSync, cpSync, readdirSync, statSync, copyFileSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, '..');
const PUBLIC_DIR = join(PROJECT_ROOT, 'public');

// Source locations
const SOURCES = {
    // Git-tracked sources (always present inside yakmesh-node)
    dashboard: {
        src: join(PROJECT_ROOT, 'dashboard', 'index.html'),
        dest: join(PUBLIC_DIR, 'dashboard', 'index.html'),
        type: 'file',
        required: true,
        label: 'Dashboard',
    },
    assets: {
        src: join(PROJECT_ROOT, 'assets'),
        dest: join(PUBLIC_DIR, 'assets'),
        type: 'dir',
        required: true,
        label: 'Logos & brand assets',
    },

    // Build artifacts from sibling projects (gitignored in public/)
    c2c: {
        src: join(PROJECT_ROOT, '..', 'c2c', 'client', 'public', 'assets'),
        dest: join(PUBLIC_DIR, 'c2c', 'assets'),
        type: 'dir',
        required: false,
        label: 'C2C game art',
    },
    yakai: {
        src: join(PROJECT_ROOT, '..', 'yakai', 'client', 'public'),
        dest: join(PUBLIC_DIR, 'yakai'),
        type: 'dir',
        filter: /\.png$/i,   // Only PNG portraits
        required: false,
        label: 'YakAI portraits',
    },
};

/**
 * Count files recursively
 */
function countFiles(dir) {
    if (!existsSync(dir)) return 0;
    let count = 0;
    for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        const stat = statSync(full);
        if (stat.isDirectory()) count += countFiles(full);
        else count++;
    }
    return count;
}

/**
 * Format bytes
 */
function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

/**
 * Get total size of a directory
 */
function dirSize(dir) {
    if (!existsSync(dir)) return 0;
    let total = 0;
    for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        const stat = statSync(full);
        if (stat.isDirectory()) total += dirSize(full);
        else total += stat.size;
    }
    return total;
}

/**
 * Main build
 */
function buildPublic() {
    console.log('📁 YAKMESH Public Web Root Builder');
    console.log('==================================\n');

    // Ensure public/ exists
    mkdirSync(PUBLIC_DIR, { recursive: true });

    let totalFiles = 0;
    let totalSize = 0;

    for (const [key, source] of Object.entries(SOURCES)) {
        if (!existsSync(source.src)) {
            if (source.required) {
                console.error(`  ✗ ${source.label}: source not found — ${source.src}`);
                process.exit(1);
            }
            console.log(`  ⊘ ${source.label}: skipped (source not found)`);
            continue;
        }

        if (source.type === 'file') {
            // Single file copy
            mkdirSync(dirname(source.dest), { recursive: true });
            copyFileSync(source.src, source.dest);
            const size = statSync(source.dest).size;
            totalFiles++;
            totalSize += size;
            console.log(`  ✓ ${source.label}: 1 file (${formatSize(size)})`);

        } else if (source.type === 'dir') {
            mkdirSync(source.dest, { recursive: true });

            if (source.filter) {
                // Filtered copy — only matching files from the source root (no recursion)
                let copied = 0;
                for (const entry of readdirSync(source.src)) {
                    if (!source.filter.test(entry)) continue;
                    const srcFile = join(source.src, entry);
                    if (!statSync(srcFile).isFile()) continue;
                    copyFileSync(srcFile, join(source.dest, entry));
                    copied++;
                    totalSize += statSync(srcFile).size;
                }
                totalFiles += copied;
                console.log(`  ✓ ${source.label}: ${copied} files (${formatSize(dirSize(source.dest))})`);

            } else {
                // Full directory mirror
                cpSync(source.src, source.dest, { recursive: true, force: true });
                const count = countFiles(source.dest);
                const size = dirSize(source.dest);
                totalFiles += count;
                totalSize += size;
                console.log(`  ✓ ${source.label}: ${count} files (${formatSize(size)})`);
            }
        }
    }

    console.log('\n==================================');
    console.log(`✅ public/ ready: ${totalFiles} files, ${formatSize(totalSize)}`);
    console.log(`   ${PUBLIC_DIR}\n`);
}

buildPublic();
