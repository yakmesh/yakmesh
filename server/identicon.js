/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * Deterministic Identicon Generator
 * 
 * Generates unique 8x8 symmetric pixel-grid avatars from persistentId.
 * Uses SHA3-256 of the persistentId as the seed — same identity always
 * produces the same image across all nodes.
 * 
 * Output: Raw PNG buffer (no external dependencies).
 * 
 * @module server/identicon
 */

import { sha3_256 } from '../utils/accel.js';

// PNG constants
const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const GRID_SIZE = 8;        // 8x8 grid
const CELL_PX = 32;         // Each cell is 32x32 pixels
const IMG_SIZE = GRID_SIZE * CELL_PX; // 256x256 output
const PADDING = 16;          // Padding around grid
const TOTAL_SIZE = IMG_SIZE + PADDING * 2; // 288x288

/**
 * CRC32 lookup table for PNG chunk checksums
 */
const CRC_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        }
        table[n] = c;
    }
    return table;
})();

function crc32(buf) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < buf.length; i++) {
        crc = CRC_TABLE[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

/**
 * Create a PNG chunk
 */
function pngChunk(type, data) {
    const typeBytes = Buffer.from(type, 'ascii');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length);

    const crcInput = Buffer.concat([typeBytes, data]);
    const crcVal = crc32(crcInput);
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crcVal);

    return Buffer.concat([length, typeBytes, data, crcBuf]);
}

/**
 * Adler-32 checksum for zlib
 */
function adler32(data) {
    let a = 1, b = 0;
    for (let i = 0; i < data.length; i++) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return ((b << 16) | a) >>> 0;
}

/**
 * Wrap raw deflate data in a minimal zlib container (stored blocks, no compression)
 * For small images, stored blocks are fine and avoid needing a full deflate impl.
 */
function zlibStore(raw) {
    // zlib header: CMF=0x78 (deflate, window 32K), FLG=0x01 (no dict, check bits)
    const header = Buffer.from([0x78, 0x01]);

    // Split into stored blocks (max 65535 bytes each)
    const blocks = [];
    let offset = 0;
    while (offset < raw.length) {
        const remaining = raw.length - offset;
        const blockSize = Math.min(remaining, 65535);
        const isLast = (offset + blockSize >= raw.length) ? 1 : 0;

        const blockHeader = Buffer.alloc(5);
        blockHeader[0] = isLast;
        blockHeader.writeUInt16LE(blockSize, 1);
        blockHeader.writeUInt16LE(blockSize ^ 0xFFFF, 3);

        blocks.push(blockHeader);
        blocks.push(raw.subarray(offset, offset + blockSize));
        offset += blockSize;
    }

    // Adler-32 checksum
    const checksum = Buffer.alloc(4);
    checksum.writeUInt32BE(adler32(raw));

    return Buffer.concat([header, ...blocks, checksum]);
}

/**
 * HSL to RGB conversion
 */
function hslToRgb(h, s, l) {
    const c = (1 - Math.abs(2 * l - 1)) * s;
    const x = c * (1 - Math.abs((h / 60) % 2 - 1));
    const m = l - c / 2;

    let r, g, b;
    if (h < 60) { r = c; g = x; b = 0; }
    else if (h < 120) { r = x; g = c; b = 0; }
    else if (h < 180) { r = 0; g = c; b = x; }
    else if (h < 240) { r = 0; g = x; b = c; }
    else if (h < 300) { r = x; g = 0; b = c; }
    else { r = c; g = 0; b = x; }

    return [
        Math.round((r + m) * 255),
        Math.round((g + m) * 255),
        Math.round((b + m) * 255),
    ];
}

/**
 * Generate a deterministic color palette from a hash
 * Returns [foreground RGB, background RGB]
 */
function generatePalette(hashBytes) {
    // Primary hue from first 2 bytes (0-360)
    const hue = ((hashBytes[0] << 8) | hashBytes[1]) % 360;

    // Saturation 50-90% from byte 2
    const sat = 0.5 + (hashBytes[2] / 255) * 0.4;

    // Foreground: vibrant color
    const fg = hslToRgb(hue, sat, 0.45);

    // Background: light tint of the same hue
    const bg = hslToRgb(hue, sat * 0.3, 0.92);

    return { fg, bg };
}

/**
 * Generate the 8x8 grid pattern (left-right symmetric)
 * Returns boolean[8][8] where true = foreground pixel
 */
function generatePattern(hashBytes) {
    const grid = Array.from({ length: GRID_SIZE }, () => new Array(GRID_SIZE).fill(false));

    // Only need to generate the left half (4 columns) — mirror for symmetry
    const halfWidth = GRID_SIZE / 2;
    let bitIndex = 24; // Start after the 3 bytes used for palette

    for (let y = 0; y < GRID_SIZE; y++) {
        for (let x = 0; x < halfWidth; x++) {
            const byteIdx = Math.floor(bitIndex / 8) % hashBytes.length;
            const bitIdx = bitIndex % 8;
            const isOn = (hashBytes[byteIdx] >> bitIdx) & 1;

            grid[y][x] = !!isOn;
            grid[y][GRID_SIZE - 1 - x] = !!isOn; // Mirror

            bitIndex++;
        }
    }

    return grid;
}

/**
 * Render the grid into raw RGBA pixel data for PNG
 */
function renderPixels(grid, palette) {
    // Each PNG scanline: filter byte (0 = None) + TOTAL_SIZE * 3 bytes (RGB)
    const rawSize = TOTAL_SIZE * (1 + TOTAL_SIZE * 3);
    const raw = Buffer.alloc(rawSize);

    for (let py = 0; py < TOTAL_SIZE; py++) {
        const rowOffset = py * (1 + TOTAL_SIZE * 3);
        raw[rowOffset] = 0; // Filter: None

        for (let px = 0; px < TOTAL_SIZE; px++) {
            const pixOffset = rowOffset + 1 + px * 3;

            // Check if inside grid area
            const gx = Math.floor((px - PADDING) / CELL_PX);
            const gy = Math.floor((py - PADDING) / CELL_PX);

            let color;
            if (gx >= 0 && gx < GRID_SIZE && gy >= 0 && gy < GRID_SIZE &&
                px >= PADDING && py >= PADDING && px < PADDING + IMG_SIZE && py < PADDING + IMG_SIZE) {
                color = grid[gy][gx] ? palette.fg : palette.bg;
            } else {
                color = palette.bg;
            }

            raw[pixOffset] = color[0];
            raw[pixOffset + 1] = color[1];
            raw[pixOffset + 2] = color[2];
        }
    }

    return raw;
}

/**
 * Generate a PNG identicon from a persistentId
 * 
 * @param {string} persistentId - The 144T persistent identity string
 * @param {number} [size] - Unused, maintained for API compatibility
 * @returns {Buffer} PNG image buffer
 */
export function generateIdenticon(persistentId) {
    // Hash the persistentId with SHA3-256 for uniformly distributed seed bytes
    const hashHex = sha3_256(persistentId);
    const hashBytes = Buffer.from(hashHex, 'hex');

    // Generate palette and pattern from hash
    const palette = generatePalette(hashBytes);
    const grid = generatePattern(hashBytes);

    // Render to pixels
    const rawPixels = renderPixels(grid, palette);

    // Compress with stored zlib blocks
    const compressed = zlibStore(rawPixels);

    // Build PNG file
    // IHDR: width, height, bit depth (8), color type (2=RGB), compression, filter, interlace
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(TOTAL_SIZE, 0);
    ihdr.writeUInt32BE(TOTAL_SIZE, 4);
    ihdr[8] = 8;   // 8-bit
    ihdr[9] = 2;   // RGB
    ihdr[10] = 0;  // deflate
    ihdr[11] = 0;  // default filter
    ihdr[12] = 0;  // no interlace

    const iend = Buffer.alloc(0);

    return Buffer.concat([
        PNG_SIGNATURE,
        pngChunk('IHDR', ihdr),
        pngChunk('IDAT', compressed),
        pngChunk('IEND', iend),
    ]);
}

export default { generateIdenticon };
