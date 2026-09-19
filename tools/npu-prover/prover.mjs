#!/usr/bin/env node
/*
 * YakMesh NPU Execution Prover — Windows backend.
 *
 * Serves the same GET /npu/proof?n=<N>&nonce=<challenge> contract as
 * rust-embed (:9997), backed by ONNX Runtime instead of XRT. The NPU is
 * reached through DirectML (AMD XDNA Windows driver); a CPU-EP fallback
 * is reported honestly via the kernel label.
 *
 * Same proof semantics as the XRT path:
 *   nonce → xorshift64* → deterministic fp16 inputs → N timed MatMul
 *   dispatches → FNV-1a-64 digest of the output tile. The digest only
 *   exists if the kernel actually ran; two identities sharing one
 *   device serialize on its queue and fail the timing envelope.
 *
 *   node tools/npu-prover/prover.mjs [--port 9997]
 */
import http from 'node:http';
import { execSync } from 'node:child_process';
import * as ort from 'onnxruntime-node';

// The 64×64 fp16 MatMul model, embedded — hashed with this file by the
// oracle (unlike a loose .onnx asset), so the workload itself is
// tamper-evident. Regenerate with tools/npu-prover/gen-model.mjs.
const MODEL_B64 = 'CAg6ZwoRCgFBCgFCEgFDIgZNYXRNdWwSE3lha21lc2gtZ2VtbTY0LWZwMTZaEwoBQRIOCgwIChIICgIIQAoCCEBaEwoBQhIOCgwIChIICgIIQAoCCEBiEwoBQxIOCgwIChIICgIIQAoCCEBCAhAN';
const MODEL_BYTES = new Uint8Array(Buffer.from(MODEL_B64, 'base64'));
const DIM = 64;
const PORT = Number(process.argv[process.argv.indexOf('--port') + 1]) || 9997;

// ─── fp16 / digest / PRNG primitives ─────────────────────────────────────────

function f32to16(v) {
  const f = new Float32Array(1), u = new Uint32Array(f.buffer);
  f[0] = v;
  const x = u[0];
  const s = (x >> 16) & 0x8000;
  const e = ((x >> 23) & 0xff) - 127 + 15;
  const m = x & 0x7fffff;
  if (e <= 0) return s;
  if (e >= 31) return s | 0x7c00;
  return s | (e << 10) | (m >> 13);
}

function fnv1a64(bytes) {
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < bytes.length; i++) {
    h ^= BigInt(bytes[i]);
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

function xorshift64star(seed) {
  let s = seed || 0x9e3779b97f4a7c15n;
  return () => {
    s ^= s >> 12n; s ^= s << 25n; s ^= s >> 27n;
    s &= 0xffffffffffffffffn;
    return (s * 0x2545f4914f6cdd1dn) & 0xffffffffffffffffn;
  };
}

const seedFromNonce = (nonce) => {
  // FNV-1a-64 of the nonce string → PRNG seed (deterministic per nonce)
  let h = 0xcbf29ce484222325n;
  for (const c of Buffer.from(nonce, 'utf8')) {
    h ^= BigInt(c);
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h;
};

// ─── device probe (cached once — hardware doesn't change) ────────────────────

function probeDevice() {
  const out = { generation: 'windows/onnxruntime', pci: null, pnp: null, name: null };
  try {
    const ps = execSync(
      'powershell -NoProfile -Command "Get-PnpDevice -ErrorAction SilentlyContinue | ' +
      'Where-Object { $_.FriendlyName -match \'NPU|XDNA|Ryzen.AI\' } | ' +
      'Select-Object FriendlyName,InstanceId | ConvertTo-Json -Compress"',
      { timeout: 10000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    ).trim();
    const dev = JSON.parse(ps);
    const first = Array.isArray(dev) ? dev[0] : dev;
    if (first?.InstanceId) {
      out.pnp = first.InstanceId;
      out.name = first.FriendlyName || null;
      const m = first.InstanceId.match(/VEN_([0-9A-Fa-f]{4})&DEV_([0-9A-Fa-f]{4})/);
      if (m) out.pci = `${m[1].toLowerCase()}:${m[2].toLowerCase()}`;
    }
  } catch { /* probe failed — honest nulls */ }
  return out;
}

// ─── inference session (persistent — kernel + buffers load once) ─────────────

let session = null;
let backend = null; // 'dml' | 'cpu'

async function getSession() {
  if (session) return session;
  try {
    session = await ort.InferenceSession.create(MODEL_BYTES, { executionProviders: ['dml'] });
    backend = 'dml';
  } catch {
    session = await ort.InferenceSession.create(MODEL_BYTES, { executionProviders: ['cpu'] });
    backend = 'cpu';
  }
  return session;
}

// ─── proof ────────────────────────────────────────────────────────────────────

const device = probeDevice();

async function runProof(n, nonce) {
  const s = await getSession();
  const rng = xorshift64star(seedFromNonce(nonce));

  const A = new Uint16Array(DIM * DIM);
  const B = new Uint16Array(DIM * DIM);
  for (let i = 0; i < DIM * DIM; i++) {
    // Deterministic bf16-magnitude inputs in [-2, 2) from the nonce stream
    A[i] = f32to16((Number(rng() % 4096n) / 1024) - 2);
    B[i] = f32to16((Number(rng() % 4096n) / 1024) - 2);
  }
  const inputDigest = fnv1a64(Buffer.concat([
    Buffer.from(A.buffer, A.byteOffset, A.byteLength),
    Buffer.from(B.buffer, B.byteOffset, B.byteLength),
  ]));

  const feeds = {
    A: new ort.Tensor('float16', A, [DIM, DIM]),
    B: new ort.Tensor('float16', B, [DIM, DIM]),
  };

  const times = [];
  const outputDigests = new Set();
  let lastOutput = null;
  for (let i = 0; i < n; i++) {
    const t0 = performance.now();
    const result = await s.run(feeds);
    times.push((performance.now() - t0) * 1e6); // ms → ns
    const out = new Uint8Array(result.C.data.buffer, result.C.data.byteOffset, result.C.data.byteLength);
    outputDigests.add(fnv1a64(Buffer.from(out)));
    lastOutput = out;
  }

  const sorted = [...times].sort((a, b) => a - b);
  const q = (p) => sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))];
  const mean = times.reduce((a, b) => a + b, 0) / times.length;

  return {
    status: 'ok',
    proof_of: 'execution',
    device,
    kernel: `onnxruntime-${backend} gemm64 (fp16)`,
    n_dispatches: n,
    nonce,
    digests: {
      algorithm: 'fnv1a64',
      input: inputDigest,
      output: fnv1a64(Buffer.from(lastOutput)),
      consistent_across_dispatches: outputDigests.size === 1,
    },
    timing: {
      per_dispatch_ns: {
        min: Math.round(sorted[0]),
        p50: Math.round(q(0.5)),
        p95: Math.round(q(0.95)),
        mean: Math.round(mean),
        max: Math.round(sorted[sorted.length - 1]),
      },
      wall_ns: Math.round(times.reduce((a, b) => a + b, 0)),
      envelope_hint_ns: { min: 50000, max: 500000 },
    },
  };
}

// ─── http ─────────────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (url.pathname === '/npu/proof') {
    const n = Math.min(Math.max(parseInt(url.searchParams.get('n') || '8', 10) || 8, 1), 1024);
    const nonce = url.searchParams.get('nonce') || '';
    try {
      const body = JSON.stringify(await runProof(n, nonce));
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(body);
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ status: 'error', error: String(e.message || e) }));
    }
  } else if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' })
      .end(JSON.stringify({ status: 'ok', backend, device }));
  } else {
    res.writeHead(404).end();
  }
});

// Warm the session so the first request isn't a cold-start outlier
getSession().then(() => {
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`[npu-prover] ${backend} backend — listening on http://127.0.0.1:${PORT}/npu/proof`);
    console.log(`[npu-prover] device: ${device.name || 'unidentified'} (${device.pnp || 'no pnp id'})`);
  });
}).catch(e => {
  console.error('[npu-prover] failed to create inference session:', e);
  process.exit(1);
});
