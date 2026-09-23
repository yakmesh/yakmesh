/**
 * YakOS MKC Client — Math Kernel Complex access (vendored from
 * yakos-dna-spiral/mkc.mjs — the canonical JS client for the pq-bridge
 * MKC endpoints at localhost:9995). Vendored so the deployable package
 * stays self-contained; keep in sync with the source.
 *
 * Surface:
 *   sha256 / sha256Batch          MLIR_AIE_SHA256 (0x9d0)
 *   sha3_256 / sha3_256Batch      MLIR_AIE_KECCAK/KECU64 (0x970/0x972)
 *   gf256, gf4Mul, f3, rsParity  MLIR_AIE_FIELD  (0x9e0)
 *   aes*                          MLIR_AIE_AES256 (0x9a0) CTR+GCM
 *   tribhuj*                      MLIR_AIE_TRIBH  (0x9c0)
 *   run / runTiles                MLIR_AIE_MKC    (0x9f0) scripted VM
 *
 * Honest-device rule: every response carries `device` — "npu" is
 * measured on-tile execution, "cpu" a real fallback, "unavailable" a
 * refusal. NPU-only surfaces (tribhuj, mkc) throw when the ctx is
 * down rather than fake a result.
 *
 * @module utils/mkc
 * @version 0.1.0
 */

const BRIDGE_URL = process.env.YAKOS_PQ_BRIDGE
  || process.env.YAKOS_PQ_BRIDGE_URL
  || 'http://127.0.0.1:9995';

// ── VM opcodes (MLIR_AIE_MKC, 0x9f0) ─────────────────────────────────
export const OP = {
    nop: 0, ld: 1, mov: 2, xor: 3, g256m: 4, g256i: 5, aff: 6,
    gf4m: 7, f3a: 8, f3m: 9, sha256: 10, rsp: 11, cmp: 12,
    emit: 13, sha3: 14, halt: 15, seti: 16, setn: 17, perm: 18,
    emitat: 19,
};

// VM status bits
export const VPASS = 0x1, VFAIL = 0x2, HALTED = 0x4;

/**
 * Build one VM insn: [op, dst, src, flags, imm].
 * `op` accepts a name ('sha256') or number. Buffers 0..3 are per-tile
 * resident 512B scratch — they persist across calls (chained proofs).
 */
export function ins(op, dst = 0, src = 0, flags = 0, imm = 0) {
    return [op, dst, src, flags, imm];
}

export class MkcError extends Error {}

/** Check bridge reachability. */
export async function isAvailable() {
    try {
        const r = await fetch(`${BRIDGE_URL}/health`,
                              { signal: AbortSignal.timeout(2000) });
        return r.ok;
    } catch { return false; }
}

async function post(ep, body) {
    let r;
    try {
        r = await fetch(`${BRIDGE_URL}/${ep}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(30000),
        });
    } catch (e) {
        throw new MkcError(`${ep}: unreachable (${e.message})`);
    }
    const j = await r.json().catch(() => ({}));
    if (!r.ok)
        throw new MkcError(`${ep}: HTTP ${r.status} ${JSON.stringify(j)}`);
    if (j.error) throw new MkcError(`${ep}: ${j.error}`);
    return j;
}

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));

// ── hashes ────────────────────────────────────────────────────────────

/** SHA-256, any length (resident tile0 stream). -> {digest, device} */
export async function sha256(data) {
    const r = await post('sha256', { action: 'hash', data: b64(data) });
    return { digest: unb64(r.digest), device: r.device };
}

/** SHA-256 batch — each msg <=1036B, 16-wide on tiles. */
export async function sha256Batch(msgs) {
    const r = await post('sha256',
                         { action: 'batch', messages: msgs.map(b64) });
    return { digests: r.digests.map(unb64), device: r.device };
}

/** SHA3-256 on the resident Keccak sponge. */
export async function sha3_256(data) {
    return (await sha3_256Batch([data])).digests[0];
}

export async function sha3_256Batch(msgs) {
    const r = await post('sha3-256', { messages: msgs.map(b64) });
    return { digests: r.digests.map(unb64), device: r.device };
}

// ── AVOTH (MLIR_AIE_AVOTH) — wormhole-sealed quaternary sponge ───────

/** Context → 4 public quats (0..3). Matches utils/avoth-bridge.js
 *  sealFromContext: SHA-256 first byte → 4 quats. Public by design —
 *  a wax seal, not a key (AVOTH-SPEC §2.8). */
export async function sealFromContext(context) {
    const { createHash } = await import('crypto');
    const b = createHash('sha256')
        .update(typeof context === 'string' ? context : Buffer.from(context))
        .digest()[0];
    return [(b >> 6) & 3, (b >> 4) & 3, (b >> 2) & 3, b & 3];
}

/** AVOTH batch hash. seals: one [q,q,q,q] per message — the wormhole
 *  seal is read every round, never written; it rides all 24 rounds and
 *  the digest binds (message, seal) jointly. → {digests: hex[], device} */
export async function avothBatch(msgs, seals = null, device = null) {
    const body = { messages: msgs.map(b64) };
    if (seals) body.seals = seals;
    if (device) body.device = device;
    const r = await post('avoth/batch-hash', body);
    return { digests: r.digests, device: r.device };
}

/** Sealed AVOTH of one message → {hash: hex, device} */
export async function avoth(data, seal = null, device = null) {
    const r = await avothBatch([data], seal ? [seal] : null, device);
    return { hash: r.digests[0], device: r.device };
}

// ── small-field engine (MLIR_AIE_FIELD) ──────────────────────────────

async function field(body) {
    const r = await post('field', body);
    return { result: unb64(r.result), device: r.device };
}

/** GF(2^8) multiply, poly 0x11b. pairs = [[a,b],...] <=512. */
export async function gf256MulPairs(pairs) {
    return field({ action: 'gf256_mul', pairs });
}

export async function gf256Mul(a, b) {
    return (await gf256MulPairs([[a, b]])).result[0];
}

/** Multiplicative inverse per byte (0 -> 0). */
export async function gf256Inv(data) {
    return field({ action: 'gf256_inv', data: [...data] });
}

/**
 * GFNI affine: out_i = parity(mat_row_i & x) ^ add.
 * mat = 8 row-mask bytes (AES S-box rows F1 E3 C7 8F 1F 3E 7C F8,
 * add 0x63 reproduces S(x) when applied to x^-1).
 */
export async function gf256Affine(data, mat, add = 0) {
    if (mat.length !== 8) throw new MkcError('mat must be 8 bytes');
    return field({ action: 'gf256_affine',
                   mat: [...mat], add, data: [...data] });
}

/** Packed-quat GF(4) multiply, poly x^2+x+1 (AVOTH's field). */
export async function gf4Mul(a, b) {
    if (a.length !== b.length) throw new MkcError('equal lengths');
    return field({ action: 'gf4_mul',
                   pairs: [...a].map((x, i) => [x, b[i]]) });
}

/** Packed-trit F3 add (2-bit codes {0,1,2}, 4 trits/byte). */
export async function f3Add(a, b) {
    if (a.length !== b.length) throw new MkcError('equal lengths');
    return field({ action: 'f3_add',
                   pairs: [...a].map((x, i) => [x, b[i]]) });
}

export async function f3Mul(a, b) {
    if (a.length !== b.length) throw new MkcError('equal lengths');
    return field({ action: 'f3_mul',
                   pairs: [...a].map((x, i) => [x, b[i]]) });
}

/**
 * 4-coeff Reed-Solomon parity (eval form). gen = 4 GF(2^8) generator
 * bytes. >1024B inputs chunk across tiles and combine via the
 * g^offset scaling identity.
 */
export async function rsParity(data, gen) {
    if (gen.length !== 4) throw new MkcError('gen must be 4 bytes');
    const r = await post('field', { action: 'rs_parity',
                                    gen: [...gen], data: [...data] });
    return { parity: unb64(r.parity), chunks: r.chunks,
             device: r.device };
}

// ── Tribhuj 162T routing-table match (MLIR_AIE_TRIBH) ────────────────

/** address: 162 trits {-1,0,1} OR 41B packed. */
function addrField(address) {
    if (address instanceof Uint8Array || Buffer.isBuffer(address)) {
        if (address.length !== 41)
            throw new MkcError('packed address must be 41 bytes');
        return { packed: b64(address) };
    }
    return { address: [...address] };
}

/** Write address to slot on all 16 tiles.
 *  -> {pop, epoch} — 'epoch' is the resident-state generation; store it
 *  and compare a later response's epoch to detect that a foreign kernel
 *  clobbered the on-tile table. */
export async function tribhujSet(slot, address) {
    const r = await post('tribhuj', { action: 'set', slot,
                                      ...addrField(address) });
    return { pop: r.pop, epoch: r.epoch };
}

export async function tribhujClear(slot) {
    const r = await post('tribhuj', { action: 'clear', slot });
    return { pop: r.pop, epoch: r.epoch };
}

/** Per-tile resident table sizes + epoch -> {pop, epoch}. */
export async function tribhujPop() {
    const r = await post('tribhuj', { action: 'pop' });
    return { pop: r.pop, epoch: r.epoch };
}

/** -> {tiles: 16 x 256 u16 (tierDist<<8|tritDist; 0xFFFF = invalid),
 *      epoch}. */
export async function tribhujQuery(target) {
    const r = await post('tribhuj', { action: 'query',
                                      ...addrField(target) });
    return { tiles: r.tiles, epoch: r.epoch };
}

/** -> {tiles: per-tile [{slot, trit_dist, tier_dist}] sorted, epoch}. */
export async function tribhujTopk(k, target) {
    const r = await post('tribhuj', { action: 'topk', k,
                                      ...addrField(target) });
    return { tiles: r.tiles, epoch: r.epoch };
}

// ── AES-256 (MLIR_AIE_AES256) — resident key + ctr per tile ────────────

/** Load AES-256 key into all 16 tiles' resident rk -> {kcv, epoch}
 *  (kcv = E_K(0), also the GHASH subkey H for GCM; epoch = the key's
 *  validity generation — a later differing epoch means on-tile rk was
 *  clobbered by a foreign kernel and set_key must be re-run). */
export async function aesSetKey(key) {
    const r = await post('aes', { action: 'set_key', key: b64(key) });
    return { kcv: unb64(r.kcv), epoch: r.epoch };
}

/** ECB-encrypt 16B blocks under the resident key -> {cts, epoch}. */
export async function aesEcb(blocks) {
    const r = await post('aes', { action: 'ecb', blocks: blocks.map(b64) });
    return { cts: r.blocks.map(unb64), epoch: r.epoch };
}

/** AES-256-CTR. iv = 16B counter start; key optional (loads resident rk
 *  first). -> {data, nextCtr, epoch, device}. */
export async function aesCtr(data, iv, key = null) {
    const body = { action: 'ctr', data: b64(data), iv: b64(iv) };
    if (key) body.key = b64(key);
    const r = await post('aes', body);
    return { data: unb64(r.data), nextCtr: unb64(r.next_ctr),
             epoch: r.epoch, device: r.device };
}

/** AES-256-GCM encrypt composed on-silicon (CTR + GHASH resident
 *  kernels). iv = 12B (96-bit J0 form). -> {ct, tag, device}. */
export async function aesGcm(key, iv, data, aad = new Uint8Array()) {
    const r = await post('aes', { action: 'gcm', key: b64(key),
                                  iv: b64(iv), data: b64(data),
                                  aad: b64(aad) });
    return { ct: unb64(r.ct), tag: unb64(r.tag), device: r.device };
}

/** Decrypt + verify a GCM record on-silicon -> {ok, pt, device}
 *  (pt is null when the tag doesn't verify). */
export async function aesGcmVerify(key, iv, ct, tag,
                                   aad = new Uint8Array()) {
    const r = await post('aes', { action: 'gcm_verify', key: b64(key),
                                  iv: b64(iv), ct: b64(ct), tag: b64(tag),
                                  aad: b64(aad) });
    return { ok: r.ok, pt: r.pt ? unb64(r.pt) : null, device: r.device };
}

// ── scripted VM (MLIR_AIE_MKC, 0x9f0) ────────────────────────────────

/**
 * Run one script on tile0 (broadcast=true -> all 16 tiles).
 * script = array of ins()/dicts/[op,dst,src,flags,imm].
 * -> [{status, emitted, data:Uint8Array}] x16. Resident scratch
 * buffers persist across calls — scripts can consume earlier results.
 */
export async function run(script, data = new Uint8Array(),
                          broadcast = false) {
    const r = await post('mkc', { script, data: b64(data), broadcast });
    return r.tiles.map(t => ({ status: t.status, emitted: t.emitted,
                               data: unb64(t.result || '') }));
}

/**
 * Heterogeneous per-tile run: tileScripts = {tile: script},
 * tileData = {tile: Uint8Array}. Absent tiles get an empty program.
 */
export async function runTiles(tileScripts, tileData = {}) {
    const td = {};
    for (const [t, d] of Object.entries(tileData)) td[t] = b64(d);
    const r = await post('mkc',
                         { tile_scripts: tileScripts, tile_data: td });
    return r.tiles.map(t => ({ status: t.status, emitted: t.emitted,
                               data: unb64(t.result || '') }));
}

/**
 * sha256 -> GFNI affine -> sha3 in ONE launch (no host round-trip).
 * Default transform reproduces the AES S-box pipeline shape.
 */
// ── split-role image (MLIR_AIE_CRYSTAL, 0xa00) ───────────────────────
// One PDI, 16 fixed-role tiles — heterogeneous jobs in ONE dispatch.
// Resident state persists across ALL crystal launches (the PDI never
// reloads internally). Tile roles:
//   0,1 tribh | 2,3 aes | 4 kecu64 | 5 ghash | 6 sha256 | 7 field
//   8-11,15 mkc | 12 ypc | 13 seal | 14 ntt
export const CRYSTAL_TILES = {
    tribh: [0, 1], aes: [2, 3], kecu64: [4], ghash: [5], sha256: [6],
    field: [7], mkc: [8, 9, 10, 11, 15], ypc: [12], seal: [13], ntt: [14],
};

/**
 * Heterogeneous crystal dispatch: jobs = [{svc, rec:Uint8Array}] — the
 * tile's NATIVE record format; optional `tile:N` selects a replica.
 * One job per tile per dispatch. -> {outs:{tile:Uint8Array}, epoch,
 * device}
 */
export async function crystal(jobs) {
    const r = await post('crystal', {
        jobs: jobs.map(j => ({
            svc: j.svc, rec: b64(j.rec),
            ...(j.tile !== undefined ? { tile: j.tile } : {}),
        })),
    });
    const outs = {};
    for (const [t, o] of Object.entries(r.outs || {})) outs[+t] = unb64(o);
    return { outs, epoch: r.epoch, device: r.device };
}

/** Role map + epoch for the crystal image. */
export async function crystalStatus() {
    return post('crystal', { action: 'status' });
}

export async function sha256AffineSha3(data, mat = null, add = 0x63) {
    if (!mat) mat = new Uint8Array(
        [0xF1, 0xE3, 0xC7, 0x8F, 0x1F, 0x3E, 0x7C, 0xF8]);
    const combo = new Uint8Array([...mat, add, ...data]);
    const tiles = await run([
        ins('ld', 0), ins('mov', 3, 0, 0, 9),
        ins('sha256', 1, 0, 0, combo.length),
        ins('aff', 1, 3, 0, 32),
        ins('sha3', 2, 1, 0, 32),
        ins('emit', 0, 2, 0, 32),
    ], combo);
    const t = tiles[0];
    if ((t.status & HALTED) || t.emitted !== 32)
        throw new MkcError(`pipeline failed: status=0x${t.status.toString(16)}`);
    return t.data;
}

export default {
    OP, VPASS, VFAIL, HALTED, ins, isAvailable,
    sha256, sha256Batch, sha3_256, sha3_256Batch,
    sealFromContext, avothBatch, avoth,
    gf256Mul, gf256MulPairs, gf256Inv, gf256Affine,
    gf4Mul, f3Add, f3Mul, rsParity,
    aesSetKey, aesEcb, aesCtr, aesGcm, aesGcmVerify,
    tribhujSet, tribhujClear, tribhujPop, tribhujQuery, tribhujTopk,
    run, runTiles, sha256AffineSha3,
    CRYSTAL_TILES, crystal, crystalStatus,
};
