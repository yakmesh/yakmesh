/**
 * UPDATE TRANSFER — package fetch/serve over the mesh
 *
 * The "get the bytes" half of the update pipeline. An announcer stages
 * packages under data/packages/<sha256>.zip; a node that has opted in
 * (operator accepted the offer) pulls it in chunks from the announcer
 * via direct sendTo messages — never gossip-flooded.
 *
 * Wire protocol (direct messages, ANNEX-encrypted in transit):
 *   fetcher → announcer:  update:fetch  {transferId, packageSha256}
 *   announcer → fetcher:  update:chunk  {transferId, seq, total, data:b64}
 *   announcer → fetcher:  update:done   {transferId, packageSha256}
 *   announcer → fetcher:  update:error  {transferId, error}
 *
 * Integrity is end-to-end: the fetcher verifies SHA-256 of the assembled
 * bytes against packageSha256 from the signed proposal. Serving bytes to
 * any verified same-network peer is safe — a tampered package fails the
 * hash check at receipt (and a wrong-codebase package yields a different
 * network anyway; it cannot impersonate, only fail to peer).
 */

import { createHash } from 'node:crypto';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { mkdir, readFile, writeFile, copyFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createLogger } from './logger.js';

const log = createLogger('mesh:update-transfer');

// ANNEX serializes ciphertext as hex (2×) around b64 JSON (4/3×) plus
// ~18KB signature/cert overhead (ML-DSA sig + tribhuj cert, hex).
// Wire string ≈ 2.67×CHUNK + 18KB must stay < 100KB (maxStringLength):
// 20KB chunk → ~90KB wire. ~950 msgs for 19MB — fine over LAN with pacing.
const CHUNK_BYTES = 20 * 1024;
const FETCH_TIMEOUT_MS = 120000;       // whole-transfer timeout
const IDLE_TIMEOUT_MS = 30000;         // between chunks

export const UPDATE_MSG = {
  FETCH: 'update:fetch',
  CHUNK: 'update:chunk',
  DONE: 'update:done',
  ERROR: 'update:error',
};

export class UpdateTransfer {
  /**
   * @param {Object} opts
   * @param {Object} opts.mesh    - MandalaNetwork (sendTo + on)
   * @param {string} opts.packageDir - dir holding staged <sha256>.zip files
   * @param {string} opts.stagingDir - dir for fetched pending-update pkg
   */
  constructor({ mesh, packageDir, stagingDir }) {
    this.mesh = mesh;
    this.packageDir = packageDir;
    this.stagingDir = stagingDir;
    this._pendingFetches = new Map();  // transferId -> {chunks, resolve, ...}
    this._serving = new Map();         // transferId -> AbortController-ish

    for (const t of Object.values(UPDATE_MSG)) {
      this.mesh.on(t, (msg, ws, from) => this._handle(t, msg, from));
    }
  }

  // ----------------------------------------------------------
  // Server side — stage + serve
  // ----------------------------------------------------------

  /**
   * Stage a package for serving: copy into packageDir keyed by sha256.
   * @returns {Promise<{packageSha256:string, packageSize:number}>}
   */
  async stagePackage(filePath) {
    const bytes = await readFile(filePath);
    const packageSha256 = createHash('sha256').update(bytes).digest('hex');
    await mkdir(this.packageDir, { recursive: true });
    const dest = join(this.packageDir, `${packageSha256}.zip`);
    if (!existsSync(dest)) await copyFile(filePath, dest);
    return { packageSha256, packageSize: bytes.length };
  }

  hasPackage(packageSha256) {
    return existsSync(join(this.packageDir, `${packageSha256}.zip`));
  }

  async _serve(transferId, requester, packageSha256) {
    const file = join(this.packageDir, `${packageSha256}.zip`);
    if (!existsSync(file)) {
      this.mesh.sendTo(requester, {
        type: UPDATE_MSG.ERROR, transferId,
        error: 'package not staged on this node',
      });
      return;
    }

    const size = statSync(file).size;
    const total = Math.ceil(size / CHUNK_BYTES);
    log.info('UPDATE: serving package', {
      to: requester.slice(-8), sha256: packageSha256.slice(0, 12), total,
    });

    const stream = createReadStream(file, { highWaterMark: CHUNK_BYTES });
    let seq = 0;
    try {
      for await (const chunk of stream) {
        this.mesh.sendTo(requester, {
          type: UPDATE_MSG.CHUNK,
          transferId, seq, total,
          data: chunk.toString('base64'),
        });
        seq++;
        // Pace the stream — 400+ back-to-back sends would starve the
        // event loop and overrun the receiver's processing.
        if (seq % 16 === 0) await new Promise(r => setTimeout(r, 25));
      }
      this.mesh.sendTo(requester, { type: UPDATE_MSG.DONE, transferId, packageSha256 });
    } catch (err) {
      this.mesh.sendTo(requester, {
        type: UPDATE_MSG.ERROR, transferId, error: err.message,
      });
    }
  }

  // ----------------------------------------------------------
  // Client side — fetch + verify + stage
  // ----------------------------------------------------------

  /**
   * Pull a package from a peer and verify it end-to-end.
   * @param {string} fromNodeId - announcer (or any peer staging the pkg)
   * @param {string} packageSha256 - expected SHA-256 of the zip
   * @returns {Promise<{path:string, packageSha256:string, size:number}>}
   */
  fetchPackage(fromNodeId, packageSha256) {
    return new Promise((resolve, reject) => {
      const transferId = randomBytes(8).toString('hex');
      const state = {
        resolve, reject, fromNodeId, packageSha256,
        chunks: new Map(), total: null,
        deadline: setTimeout(() => this._fail(transferId, 'transfer timeout'), FETCH_TIMEOUT_MS),
        idle: null,
      };
      this._pendingFetches.set(transferId, state);
      this.mesh.sendTo(fromNodeId, {
        type: UPDATE_MSG.FETCH, transferId, packageSha256,
      });
    });
  }

  _fail(transferId, error) {
    const st = this._pendingFetches.get(transferId);
    if (!st) return;
    clearTimeout(st.deadline);
    clearTimeout(st.idle);
    this._pendingFetches.delete(transferId);
    st.reject(new Error(`update fetch failed: ${error}`));
  }

  async _complete(transferId) {
    const st = this._pendingFetches.get(transferId);
    if (!st) return;
    clearTimeout(st.deadline);
    clearTimeout(st.idle);
    this._pendingFetches.delete(transferId);

    try {
      const bytes = Buffer.concat(
        Array.from({ length: st.total }, (_, i) => st.chunks.get(i))
      );
      const actual = createHash('sha256').update(bytes).digest('hex');
      if (actual !== st.packageSha256) {
        throw new Error(`package hash mismatch: got ${actual.slice(0, 16)}…`);
      }
      await mkdir(this.stagingDir, { recursive: true });
      const path = join(this.stagingDir, 'package.zip');
      await writeFile(path, bytes);
      st.resolve({ path, packageSha256: actual, size: bytes.length });
    } catch (err) {
      st.reject(err);
    }
  }

  // ----------------------------------------------------------
  // Message routing
  // ----------------------------------------------------------

  _handle(type, msg, from) {
    if (!msg || typeof msg !== 'object') return;

    if (type === UPDATE_MSG.FETCH) {
      // Only serve connected peers — sendTo reply implies verified peer
      if (!msg.transferId || !msg.packageSha256) return;
      this._serve(msg.transferId, from, msg.packageSha256).catch(() => { });
      return;
    }

    const st = this._pendingFetches.get(msg.transferId);
    if (!st || from !== st.fromNodeId) return;

    if (type === UPDATE_MSG.CHUNK) {
      if (typeof msg.seq !== 'number' || typeof msg.total !== 'number' || !msg.data) return;
      st.total = msg.total;
      st.chunks.set(msg.seq, Buffer.from(msg.data, 'base64'));
      clearTimeout(st.idle);
      st.idle = setTimeout(() => this._fail(msg.transferId, 'idle timeout'), IDLE_TIMEOUT_MS);
      if (st.chunks.size === st.total) this._complete(msg.transferId);
    } else if (type === UPDATE_MSG.DONE) {
      if (st.chunks.size === st.total) this._complete(msg.transferId);
    } else if (type === UPDATE_MSG.ERROR) {
      this._fail(msg.transferId, msg.error || 'remote error');
    }
  }
}

export default UpdateTransfer;
