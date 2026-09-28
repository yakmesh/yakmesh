#!/usr/bin/env node
/*
 * YakMesh NPU Execution Prover — Windows backend (v2, koffi/ORT C API).
 *
 * Serves the same GET /npu/proof?n=<N>&nonce=<challenge> contract as
 * rust-embed (:9997). Backends, in honesty order:
 *
 *   0. XRT-direct (xrt/final.xclbin + yak_xrt_shim.dll) — our own
 *      IRON-compiled gemm64 bf16 kernel on the C++ register_xclbin path.
 *      The C-API xclbin load is stubbed ('load_axlf: not supported') in
 *      the Windows user-mode shim, same as Linux amdxdna — the shim DLL
 *      wraps xrt::device::register_xclbin + hw_context + kernel. This is
 *      the same xclbin bytes the Linux MLIR_AIE path executes, so claims
 *      are byte-identical across OSes. Verified live on Hawk Point
 *      (driver 32.0.203.314, XRT 2.19.0): 4096/4096 bf16 gemm match.
 *   1. VitisAI EP (Ryzen AI / onnxruntime_providers_vitisai.dll) — the
 *      native XDNA provider, tried under RyzenAI's own onnxruntime.dll
 *      first (provider bridge is version-locked), then under ours.
 *      NOTE (verified 2026-09-25, RyzenAI 1.7.0 on Hawk Point): phx
 *      support is vestigial — fp16 doesn't fuse, u16 QDQ fuses then
 *      dies in to_xir_ops_pass (no u16 handler), u8 QDQ doesn't fuse
 *      at all, and the default X2 target is Strix-only. Dead on XDNA1;
 *      kept for Strix-class hosts where the EP still works.
 *   2. DML { device_filter: 'npu' } via the generic
 *      SessionOptionsAppendExecutionProvider — the DXCore/MCDM path.
 *      The NPU is a D3D12_GENERIC_ML adapter, NOT a DXGI display
 *      adapter, so it is unreachable through onnxruntime-node's deviceId
 *      (which indexes IDXGIFactory::EnumAdapters1). device_filter is
 *      only reachable via the generic provider-options API — hence the
 *      direct C-API binding.
 *      NOTE (verified 2026-09-25, ORT 1.30.0): stock onnxruntime-node
 *      Windows builds do NOT compile ENABLE_NPU_ADAPTER_ENUMERATION —
 *      ParseFilter in dml_provider_factory.cc only matches 'npu'/'any'
 *      inside that #ifdef, so this attempt always throws "Invalid
 *      Filter provided for DirectML EP device selection." Kept in the
 *      cascade because an ORT build with the flag flips it live; on
 *      stock builds the real NPU path is tier 1 (VitisAI EP).
 *   3. DML { device_filter: 'gpu' } — honest GPU tier (iGPU/dGPU).
 *   4. ORT CPU EP — honest CPU tier.
 *   5. Pure-JS fp16 GEMM — honest 'js-cpu' floor when onnxruntime.dll
 *      is absent.
 *
 * Same proof semantics as the XRT path: nonce → xorshift64* → inputs →
 * N timed MatMul dispatches → FNV-1a-64 output digest. The digest only
 * exists if the kernel ran; two identities sharing one device serialize
 * on its queue and fail the timing envelope.
 *
 *   node tools\npu-prover\prover.mjs [--port 9997]
 */
import http from 'node:http';
import { execSync, spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// koffi is dynamic — if the native module can't load, we still serve
// honest js-cpu proofs rather than dying at import time.
let koffi = null;
let koffiError = null;
try {
  koffi = (await import('koffi')).default;
} catch (e) { koffiError = String(e.message || e); }
const log = (m) => console.log(`[npu-prover] ${m}`);
log(`init: koffi ${koffi ? 'loaded' : 'FAILED: ' + koffiError}`);

// Embedded 64x64 MatMul models — fp16 first (matches the XRT bf16 tier),
// fp32 as a fallback for drivers that reject fp16 on GENERIC_ML.
// Regenerate with tools/npu-prover/gen-model.mjs (fp32: elem_type 1).
const MODEL_FP16 = Buffer.from(
  'CAg6ZwoRCgFBCgFCEgFDIgZNYXRNdWwSE3lha21lc2gtZ2VtbTY0LWZwMTZaEwoBQRIOCgwIChIICgIIQAoCCEBaEwoBQhIOCgwIChIICgIIQAoCCEBiEwoBQxIOCgwIChIICgIIQAoCCEBCAhAN',
  'base64');
const MODEL_FP32 = Buffer.from(
  'CAg6ZwoRCgFBCgFCEgFDIgZNYXRNdWwSE3lha21lc2gtZ2VtbTY0LWZwMzJaEwoBQRIOCgwIARIICgIIQAoCCEBaEwoBQhIOCgwIARIICgIIQAoCCEBiEwoBQxIOCgwIARIICgIIQAoCCEBCAhAN',
  'base64');
// QDQ-wrapped bf16 MatMul — uint16 boundary tensors carry bf16 bits
// (scale bf16=1.0, zp u16=0 → bit-transparent). This is the only MatMul
// shape vaip fuses (m_qmatmul_act_act → QMatMulDynamic on XDNA).
const MODEL_QDQ = Buffer.from(
  'CAo68QEKIAoBYQoBcwoBehIDYV9mIhBEZXF1YW50aXplTGluZWFyCiAKAWIKAXMKAXoSA2JfZiIQRGVxdWFudGl6ZUxpbmVhcgoXCgNhX2YKA2JfZhIDbV9mIgZNYXRNdWwKIAoDbV9mCgFzCgF6EgNvdXQiDlF1YW50aXplTGluZWFyEhd5YWttZXNoLWdlbW02NC1xZHEtYmYxNioLEAFCAXNKBAAAgD8qCRAEQgF6SgIAAFoTCgFhEg4KDAgEEggKAghACgIIQFoTCgFiEg4KDAgEEggKAghACgIIQGIVCgNvdXQSDgoMCAQSCAoCCEAKAghAQgIQFQ==',
  'base64');
// QDQ uint8 MatMul — same topology, era-correct XDNA1 dtype. vaip 1.7.0's
// to_xir has no u16 DequantizeLinear handler (fatal TODO on phx), so the
// u16-as-bf16 pattern fuses then dies in serialization. u8 is the dtype the
// Phoenix/Hawk Point QDQ flow was built around; scale fp32=1.0, zp u8=0, and
// the prover feeds {0,1} inputs so out = sum ≤ 64 — no clipping.
const MODEL_QDQ8 = Buffer.from(
  'CAo67gEKIAoBYQoBcwoBehIDYV9mIhBEZXF1YW50aXplTGluZWFyCiAKAWIKAXMKAXoSA2JfZiIQRGVxdWFudGl6ZUxpbmVhcgoXCgNhX2YKA2JfZhIDbV9mIgZNYXRNdWwKIAoDbV9mCgFzCgF6EgNvdXQiDlF1YW50aXplTGluZWFyEhV5YWttZXNoLWdlbW02NC1xZHEtdTgqCxABQgFzSgQAAIA/KggQAkIBekoBAFoTCgFhEg4KDAgCEggKAghACgIIQFoTCgFiEg4KDAgCEggKAghACgIIQGIVCgNvdXQSDgoMCAISCAoCCEAKAghAQgIQFQ==',
  'base64');
const DIM = 64;
const ELEMS = DIM * DIM;
const HERE = dirname(fileURLToPath(import.meta.url));
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

function f16to32(h) {
  const s = (h & 0x8000) ? -1 : 1;
  const e = (h >> 10) & 0x1f;
  const m = h & 0x3ff;
  if (e === 0) return s * m * (2 ** -24);
  if (e === 31) return m ? NaN : s * Infinity;
  return s * (1 + m / 1024) * (2 ** (e - 15));
}

// bf16 = top 16 bits of fp32 — XDNA's native float format. The QDQ model
// carries bf16 bit patterns in uint16 boundary tensors.
function f32tobf16(v) {
  const f = new Float32Array(1), u = new Uint32Array(f.buffer);
  f[0] = v;
  return (u[0] + 0x7fff + ((u[0] >> 16) & 1)) >>> 16;
}
function bf16to32(h) {
  const u = new Uint32Array(1);
  u[0] = h << 16;
  return new Float32Array(u.buffer)[0];
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
  let h = 0xcbf29ce484222325n;
  for (const c of Buffer.from(nonce, 'utf8')) {
    h ^= BigInt(c);
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h;
};

// ─── PnP probe (cached once — hardware doesn't change) ───────────────────────
// FIXED twice: (1) 'NPU|XDNA|Ryzen.AI' missed 'AMD IPU Device' → added IPU
// + PCI-ID fallback. (2) case-insensitive 'IPU' ALSO matched "USB Input
// Device" ('npu' inside "iNPUt") — a false positive that may also explain
// accel.js reporting an NPU that isn't there. Now -cmatch (case-sensitive):
// 'IPU' matches 'AMD IPU Device' but not 'Input'. PCI VEN_1022 result is
// preferred over name matches when several devices hit.

function probeDevice() {
  const out = { generation: 'windows/onnxruntime', pci: null, pnp: null, name: null };
  try {
    const ps = execSync(
      'powershell -NoProfile -Command "Get-PnpDevice -ErrorAction SilentlyContinue | ' +
      'Where-Object { $_.FriendlyName -cmatch \'NPU|XDNA|Ryzen|IPU\' -or ' +
      '$_.InstanceId -match \'VEN_1022&DEV_(1502|17F0|17F1)\' } | ' +
      'Select-Object FriendlyName,InstanceId | ConvertTo-Json -Compress"',
      { timeout: 10000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    ).trim();
    if (ps) {
      const dev = JSON.parse(ps);
      const list = Array.isArray(dev) ? dev : [dev];
      const pick = list.find((d) => /^PCI\\VEN_1022/i.test(d?.InstanceId || '')) || list[0];
      if (pick?.InstanceId) {
        out.pnp = pick.InstanceId;
        out.name = pick.FriendlyName || null;
        const m = pick.InstanceId.match(/VEN_([0-9A-Fa-f]{4})&DEV_([0-9A-Fa-f]{4})/);
        if (m) out.pci = `${m[1].toLowerCase()}:${m[2].toLowerCase()}`;
        if (list.length > 1) out.pnp_all = list.map((d) => d.InstanceId);
      }
    }
  } catch { /* probe failed — honest nulls */ }
  return out;
}

// ─── koffi plumbing helpers ──────────────────────────────────────────────────

// Alloc a NUL-terminated C string that stays alive for the process.
const _keep = [];
function cstr(s) {
  const p = koffi.alloc('char', s.length + 1);
  new Uint8Array(koffi.view(p, s.length + 1)).set(Buffer.from(s + '\0', 'utf8'));
  _keep.push(p);
  return p;
}

// Alloc a void*-sized out cell; decode() reads the stored pointer after a call.
function cell() { return koffi.alloc('void *', 1); }
const cellVal = (c) => koffi.decode(c, 'void *');

// Build a void*[] pointer table from koffi pointers.
function ptrTable(ptrs) {
  const t = koffi.alloc('void *', ptrs.length);
  new BigUint64Array(koffi.view(t, ptrs.length * 8))
    .set(ptrs.map((p) => koffi.address(p)));
  _keep.push(t);
  return t;
}

const readCStr = (p, cap = 512) => {
  const v = new Uint8Array(koffi.view(p, cap));
  const nul = v.indexOf(0);
  return Buffer.from(v.subarray(0, nul < 0 ? cap : nul)).toString('utf8');
};

// ─── DXCore adapter enumeration (mirrors ORT's DML adapter path) ─────────────
// ORT device_filter uses: D3D12_GENERIC_ML list → classify NPU as
// (IsHardware && !D3D12_GRAPHICS). We enumerate the same list so the
// reported adapter_desc/luid is the adapter ORT actually binds.
//
// COM vtables (x64, all calls have `this` as arg 0):
//   IDXCoreAdapterFactory: [QI,AddRef,Release,CreateAdapterList,GetAdapterByLuid,...]
//   IDXCoreAdapterList:    [QI,AddRef,Release,GetAdapter,GetAdapterCount,IsStale,...]
//   IDXCoreAdapter:        [QI,AddRef,Release,IsValid,IsAttributeSupported,
//                           IsPropertySupported,GetProperty,GetPropertySize,...]

const guidBytes = (g) => {
  const m = g.replace(/[{}-]/g, '');
  const b = Buffer.alloc(16);
  b.writeUInt32LE(parseInt(m.slice(0, 8), 16), 0);
  b.writeUInt16LE(parseInt(m.slice(8, 12), 16), 4);
  b.writeUInt16LE(parseInt(m.slice(12, 16), 16), 6);
  for (let i = 0; i < 8; i++) b[8 + i] = parseInt(m.slice(16 + i * 2, 18 + i * 2), 16);
  return b;
};
const guidPtr = (g) => { const p = koffi.alloc('char', 16); new Uint8Array(koffi.view(p, 16)).set(guidBytes(g)); _keep.push(p); return p; };

const IID = {
  IDXCoreAdapterFactory: '78ee5945-c36e-4b13-a669-005dd11c0f06',
  IDXCoreAdapterList: '526c7776-40e9-459b-b711-f32ad76dfc28',
  IDXCoreAdapter: 'f0db4c7f-fe5a-42a2-bd62-f2a6cf6fc83e',
  ATTR_GENERIC_ML: 'b71b0d41-1088-422f-a27c-0250b7d3a988',
  ATTR_CORE_COMPUTE: '248e2800-a793-4724-abaa-23a6de1be090',
  ATTR_D3D12_GRAPHICS: '0c9ece4d-2f6e-4f01-8c96-e89e331b47b1',
  ATTR_TYPE_NPU: 'd46140c4-add7-451b-9e56-06fe8c3b58ed',
};

function enumDxCore() {
  const adapters = [];
  if (!koffi) return adapters;
  let dx;
  try { dx = koffi.load('dxcore.dll'); } catch { return adapters; }
  try {
    const CreateFactory = dx.func('int32 DXCoreCreateAdapterFactory(void *riid, void **out)');
    const facCell = cell();
    if (CreateFactory(guidPtr(IID.IDXCoreAdapterFactory), facCell) < 0) return adapters;
    const factory = cellVal(facCell);
    const fvt = koffi.decode(koffi.decode(factory, 'void *'), 'void *', 8);
    const CreateAdapterList = koffi.proto('int32 DxCreateAdapterList(void *self, uint32 n, void *attrs, void *riid, void **out)');
    const GetAdapterCount = koffi.proto('uint32 DxGetAdapterCount(void *self)');
    const GetAdapter = koffi.proto('int32 DxGetAdapter(void *self, uint32 i, void *riid, void **out)');
    const IsAttrSupported = koffi.proto('uint8 DxIsAttrSupported(void *self, void *attr)');
    const IsPropSupported = koffi.proto('uint8 DxIsPropSupported(void *self, uint32 prop)');
    const GetProperty = koffi.proto('int32 DxGetProperty(void *self, uint32 prop, uint64 size, void *data)');
    const GetPropertySize = koffi.proto('int32 DxGetPropertySize(void *self, uint32 prop, void *size)');

    // attribute list: GENERIC_ML (what ORT prefers), fallback CORE_COMPUTE
    let list = null;
    for (const attr of [IID.ATTR_GENERIC_ML, IID.ATTR_CORE_COMPUTE]) {
      const lc = cell();
      const attrPtr = guidPtr(attr);
      if (koffi.call(fvt[3], CreateAdapterList, factory, 1, attrPtr, guidPtr(IID.IDXCoreAdapterList), lc) < 0) continue;
      list = cellVal(lc);
      if (list && koffi.call(koffi.decode(koffi.decode(list, 'void *'), 'void *', 9)[4], GetAdapterCount, list) > 0) break;
      list = null;
    }
    if (!list) return adapters;

    const lvt = koffi.decode(koffi.decode(list, 'void *'), 'void *', 9);
    const count = koffi.call(lvt[4], GetAdapterCount, list);
    for (let i = 0; i < count; i++) {
      const ac = cell();
      if (koffi.call(lvt[3], GetAdapter, list, i, guidPtr(IID.IDXCoreAdapter), ac) < 0) continue;
      const a = cellVal(ac);
      const avt = koffi.decode(koffi.decode(a, 'void *'), 'void *', 13);
      const rec = { index: i, desc: null, luid: null, vendor_id: null, device_id: null, driver_version: null, is_hardware: null, is_npu: null };
      try {
        // DriverDescription (prop 2) — string
        if (koffi.call(avt[5], IsPropSupported, a, 2)) {
          const sc = cell();
          if (koffi.call(avt[7], GetPropertySize, a, 2, sc) >= 0) {
            const sz = Number(new BigUint64Array(koffi.view(sc, 8))[0]);
            const buf = koffi.alloc('char', sz);
            if (koffi.call(avt[6], GetProperty, a, 2, BigInt(sz), buf) >= 0) {
              rec.desc = Buffer.from(new Uint8Array(koffi.view(buf, sz)).subarray(0, Math.max(0, sz - 1))).toString('utf8');
            }
          }
        }
        // InstanceLuid (prop 0) — 8 bytes
        const lb = koffi.alloc('char', 8);
        if (koffi.call(avt[6], GetProperty, a, 0, 8n, lb) >= 0) {
          const v = new BigUint64Array(koffi.view(lb, 8));
          rec.luid = '0x' + v[0].toString(16);
        }
        // DriverVersion (prop 1) — LARGE_INTEGER
        const db = koffi.alloc('char', 8);
        if (koffi.call(avt[6], GetProperty, a, 1, 8n, db) >= 0) {
          const v = new BigUint64Array(koffi.view(db, 8))[0];
          rec.driver_version = `${v >> 48n}.${(v >> 32n) & 0xffffn}.${(v >> 16n) & 0xffffn}.${v & 0xffffn}`;
        }
        // HardwareIDParts (prop 14) — 5 x u32
        const hb = koffi.alloc('char', 20);
        if (koffi.call(avt[6], GetProperty, a, 14, 20n, hb) >= 0) {
          const u = new Uint32Array(koffi.view(hb, 20));
          rec.vendor_id = '0x' + u[0].toString(16);
          rec.device_id = '0x' + u[1].toString(16);
        }
        // IsHardware (prop 11) — bool
        const hw = koffi.alloc('char', 1);
        if (koffi.call(avt[6], GetProperty, a, 11, 1n, hw) >= 0) {
          rec.is_hardware = !!new Uint8Array(koffi.view(hw, 1))[0];
        }
        // ORT's IsNPU: hardware && !D3D12_GRAPHICS
        const hasGfx = !!koffi.call(avt[4], IsAttrSupported, a, guidPtr(IID.ATTR_D3D12_GRAPHICS));
        const hasNpuAttr = !!koffi.call(avt[4], IsAttrSupported, a, guidPtr(IID.ATTR_TYPE_NPU));
        rec.is_npu = rec.is_hardware !== false && (!hasGfx || hasNpuAttr);
      } catch { /* per-adapter failure — keep what we have */ }
      adapters.push(rec);
    }
  } catch { /* enumeration failed — return partial */ }
  return adapters;
}

// ─── ORT C API backend (koffi → onnxruntime.dll) ─────────────────────────────
// OrtApi function-table indices for ORT_API_VERSION 24 (onnxruntime 1.24.x),
// extracted from onnxruntime_c_api.h.

const ORT_API_VERSION = 24;
const API_SIZE = 300;
const API = {
  GetErrorMessage: 2, CreateEnv: 3, CreateSessionFromArray: 8, Run: 9,
  CreateSessionOptions: 10, SetSessionLogSeverityLevel: 22,
  SessionGetInputCount: 30, SessionGetOutputCount: 31,
  SessionGetInputName: 36, SessionGetOutputName: 37,
  CreateTensorWithDataAsOrtValue: 49, GetTensorMutableData: 51,
  GetTensorTypeAndShape: 65, CreateCpuMemoryInfo: 69,
  AllocatorFree: 76, GetAllocatorWithDefaultOptions: 78,
  ReleaseEnv: 92, ReleaseStatus: 93, ReleaseMemoryInfo: 94,
  ReleaseSession: 95, ReleaseValue: 96, ReleaseSessionOptions: 100,
  AddSessionConfigEntry: 130,
  SessionOptionsAppendExecutionProvider: 216,
  AppendEpVitis: 276, // dedicated VitisAI append — exists since API v23
};
// Prototypes are registered lazily — koffi may be absent (js-cpu tier).
const P = {};
function initProtos() {
  P.CreateEnv = koffi.proto('void *OrtCreateEnv(int32 level, const char *id, void **out)');
  P.CreateSessionOptions = koffi.proto('void *OrtCreateSessionOptions(void **out)');
  P.AppendEp = koffi.proto('void *OrtAppendEp(void *so, const char *name, void *keys, void *vals, uint64 n)');
  P.CreateSessionFromArray = koffi.proto('void *OrtCreateSessionFromArray(void *env, const void *data, uint64 len, void *so, void **out)');
  P.Run = koffi.proto('void *OrtRun(void *s, void *ro, void *in_names, void *inputs, uint64 in_cnt, void *out_names, uint64 out_cnt, void *outputs)');
  P.GetIOCount = koffi.proto('void *OrtGetIOCount(void *s, uint64 *out)');
  P.GetIOName = koffi.proto('void *OrtGetIOName(void *s, uint64 i, void *alloc, void **out)');
  P.CreateCpuMemoryInfo = koffi.proto('void *OrtCreateCpuMemoryInfo(int32 mt, int32 at, void **out)');
  P.CreateTensor = koffi.proto('void *OrtCreateTensor(void *mi, void *data, uint64 len, void *shape, uint64 dims, int32 type, void **out)');
  P.GetTensorData = koffi.proto('void *OrtGetTensorData(void *v, void **out)');
  P.GetAlloc = koffi.proto('void *OrtGetAlloc(void **out)');
  P.GetErrorMessage = koffi.proto('const char *OrtGetErrorMessage(void *st)');
  P.ReleaseObj = koffi.proto('void OrtReleaseObj(void *o)');
  P.SetLogSev = koffi.proto('void *OrtSetLogSev(void *so, int32 sev)');
  P.GetApi = koffi.proto('void *OrtGetApiFn(uint32 v)');
  P.GetVersionStr = koffi.proto('void *OrtVersionStrFn(void)');
  P.AppendEpVitis = koffi.proto('void *OrtAppendEpVitisFn(void *so, void *keys, void *vals, uint64 n)');
  P.AddCfgEntry = koffi.proto('void *OrtAddCfgEntry(void *so, const char *k, const char *v)');
}

class Ort {
  constructor(dllPath) {
    this.lib = koffi.load(dllPath);
    this.version = null;
    const getApiBase = this.lib.func('void *OrtGetApiBase(void)');
    const base = getApiBase();
    const [getApi, getVer] = koffi.decode(base, 'void *', 2);
    // OrtApi is append-only — request v24, fall back to v23 (RyzenAI's
    // bundled onnxruntime.dll is 1.23.2; all indices we use are stable).
    let apiPtr = koffi.call(getApi, P.GetApi, ORT_API_VERSION);
    if (!apiPtr) apiPtr = koffi.call(getApi, P.GetApi, 23);
    if (!apiPtr) throw new Error('OrtGetApi returned null for API v24 and v23');
    this.api = koffi.decode(apiPtr, 'void *', API_SIZE);
    try { this.version = readCStr(koffi.call(getVer, P.GetVersionStr)); } catch {}
    const envCell = cell();
    this.chk(koffi.call(this.api[API.CreateEnv], P.CreateEnv, 3, 'yakmesh-npu-prover', envCell), 'CreateEnv');
    this.env = cellVal(envCell);
    const miCell = cell();
    this.chk(koffi.call(this.api[API.CreateCpuMemoryInfo], P.CreateCpuMemoryInfo, 0, 1, miCell), 'CreateCpuMemoryInfo');
    this.memInfo = cellVal(miCell);
    const alCell = cell();
    this.chk(koffi.call(this.api[API.GetAllocatorWithDefaultOptions], P.GetAlloc, alCell), 'GetAllocator');
    this.allocator = cellVal(alCell);
  }

  // Wrap a call that returns OrtStatus*: throws on error with ORT's message.
  chk(statusPtr, what) {
    if (statusPtr) {
      const msg = koffi.call(this.api[API.GetErrorMessage], P.GetErrorMessage, statusPtr);
      const s = typeof msg === 'string' ? msg : 'unknown ORT error';
      koffi.call(this.api[API.ReleaseStatus], P.ReleaseObj, statusPtr);
      throw new Error(`${what}: ${s}`);
    }
  }

  createSession(modelBytes, providerName, providerOpts, onnxType) {
    const soCell = cell();
    this.chk(koffi.call(this.api[API.CreateSessionOptions], P.CreateSessionOptions, soCell), 'CreateSessionOptions');
    const so = cellVal(soCell);
    try {
      koffi.call(this.api[API.SetSessionLogSeverityLevel], P.SetLogSev, so, 3);
      if (providerName) {
        const keys = ptrTable(Object.keys(providerOpts).map(cstr));
        const vals = ptrTable(Object.values(providerOpts).map(cstr));
        let st = koffi.call(this.api[API.SessionOptionsAppendExecutionProvider], P.AppendEp,
          so, providerName, keys, vals, Object.keys(providerOpts).length);
        // Older ORT builds (e.g. RyzenAI's 1.23.2) may not register 'VitisAI'
        // under the generic name — fall back to the dedicated entry point.
        if (st && providerName === 'VitisAI' && this.api[API.AppendEpVitis]) {
          koffi.call(this.api[API.ReleaseStatus], P.ReleaseObj, st);
          st = koffi.call(this.api[API.AppendEpVitis], P.AppendEpVitis,
            so, keys, vals, Object.keys(providerOpts).length);
        }
        this.chk(st, `AppendEP ${providerName} ${JSON.stringify(providerOpts)}`);
        // Honesty gate: if the EP can't place our op, session creation must
        // fail rather than silently run it on CPU inside this session —
        // otherwise the backend label would claim silicon it never used.
        this.chk(koffi.call(this.api[API.AddSessionConfigEntry], P.AddCfgEntry,
          so, 'session.disable_cpu_ep_fallback', '1'), 'disable_cpu_ep_fallback');
      }
      const sCell = cell();
      this.chk(koffi.call(this.api[API.CreateSessionFromArray], P.CreateSessionFromArray,
        this.env, modelBytes, BigInt(modelBytes.length), so, sCell), 'CreateSession');
      const session = cellVal(sCell);

      // resolve input/output names once (they stay valid for the session)
      const cntCell = koffi.alloc('uint64', 1);
      const rd64 = () => Number(new BigUint64Array(koffi.view(cntCell, 8))[0]);
      this.chk(koffi.call(this.api[API.SessionGetInputCount], P.GetIOCount, session, cntCell), 'InputCount');
      const nIn = rd64();
      this.chk(koffi.call(this.api[API.SessionGetOutputCount], P.GetIOCount, session, cntCell), 'OutputCount');
      const nOut = rd64();
      const names = (getter, n) => {
        const out = [];
        for (let i = 0; i < n; i++) {
          const nc = cell();
          this.chk(koffi.call(this.api[getter], P.GetIOName, session, i, this.allocator, nc), 'GetName');
          out.push(cellVal(nc)); // freed on process exit — tiny, static set
        }
        return out;
      };
      return {
        session,
        onnxType,
        inNames: names(API.SessionGetInputName, nIn),
        outNames: names(API.SessionGetOutputName, nOut),
      };
    } finally {
      koffi.call(this.api[API.ReleaseSessionOptions], P.ReleaseObj, so);
    }
  }

  // One real dispatch — a backend that can't actually execute cascades out.
  warm(sess) {
    const t = sess.onnxType === 1 ? new Float32Array(ELEMS)
      : sess.onnxType === 2 ? new Uint8Array(ELEMS) : new Uint16Array(ELEMS);
    const inA = this.makeTensor(t, sess.onnxType);
    const inB = this.makeTensor(t, sess.onnxType);
    try { this.run(sess, [inA, inB]); }
    finally {
      koffi.call(this.api[API.ReleaseValue], P.ReleaseObj, inA);
      koffi.call(this.api[API.ReleaseValue], P.ReleaseObj, inB);
    }
  }

  makeTensor(data, onnxType) {
    const shape = Buffer.alloc(16);
    shape.writeBigInt64LE(BigInt(DIM), 0);
    shape.writeBigInt64LE(BigInt(DIM), 8);
    const vCell = cell();
    this.chk(koffi.call(this.api[API.CreateTensorWithDataAsOrtValue], P.CreateTensor,
      this.memInfo, data, BigInt(data.byteLength), shape, 2, onnxType, vCell),
      'CreateTensor');
    return cellVal(vCell);
  }

  run(sess, inputs) {
    if (process.env.PROVER_DEBUG) console.error('[dbg] run: building tables');
    const inTab = ptrTable(sess.inNames);
    const valTab = ptrTable(inputs);
    const outTab = ptrTable(sess.outNames);
    const outCell = koffi.alloc('void *', sess.outNames.length);
    _keep.push(outCell);
    if (process.env.PROVER_DEBUG) console.error('[dbg] run: calling Run');
    this.chk(koffi.call(this.api[API.Run], P.Run,
      sess.session, null, inTab, valTab, inputs.length, outTab, sess.outNames.length, outCell),
      'Run');
    if (process.env.PROVER_DEBUG) console.error('[dbg] run: Run returned');
    const outs = koffi.decode(outCell, 'void *', sess.outNames.length);
    const dCell = cell();
    this.chk(koffi.call(this.api[API.GetTensorMutableData], P.GetTensorData, outs[0], dCell), 'GetTensorData');
    const dataPtr = cellVal(dCell);
    // Copy BEFORE ReleaseValue — a view over OrtValue memory dangles once freed.
    const bytes = new Uint8Array(ELEMS * (sess.onnxType === 1 ? 4 : sess.onnxType === 2 ? 1 : 2));
    bytes.set(new Uint8Array(koffi.view(dataPtr, bytes.length)));
    if (process.env.PROVER_DEBUG) console.error('[dbg] run: copied, releasing output');
    koffi.call(this.api[API.ReleaseValue], P.ReleaseObj, outs[0]);
    if (process.env.PROVER_DEBUG) console.error('[dbg] run: output released');
    return bytes;
  }
}

function findOrtDll() {
  const cands = [
    process.env.ORT_DLL,
    join(HERE, 'onnxruntime.dll'),
    join(HERE, 'bin', 'onnxruntime.dll'),
    join(HERE, '..', '..', 'node_modules', 'onnxruntime-node', 'bin', 'napi-v6', 'win32', 'x64', 'onnxruntime.dll'),
  ].filter(Boolean);
  return cands.find((p) => existsSync(p)) || null;
}

// Ryzen AI / Vitis EP install — the real XDNA provider on Windows. The
// provider dll (onnxruntime_providers_vitisai.dll) is version-locked to the
// onnxruntime.dll it shipped with, so the Vitis attempt must run under
// RyzenAI's own ort library. LoadLibrary finds provider dlls via PATH.
// Version-agnostic: scan C:\Program Files\RyzenAI\<ver>\ for the pieces,
// then fall back to a bundled copy staged at tools/npu-prover/ryzenai/
// (for machines with the IPU driver but no RyzenAI install).
function findRyzenAI() {
  const scan = (root) => {
    try {
      for (const ver of readdirSync(root).sort().reverse()) {
        const base = join(root, ver);
        const dll = join(base, 'deployment', 'onnxruntime.dll');
        if (!existsSync(dll)) continue;
        let cfg = null;
        try {
          for (const sub of readdirSync(base)) {
            const c = join(base, sub, 'vaip_config.json');
            if (existsSync(c)) { cfg = c; break; }
          }
        } catch { /* keep looking */ }
        return { dir: base, deployDir: join(base, 'deployment'), dll, cfg };
      }
    } catch { /* no install here */ }
    return null;
  };
  return scan('C:\\Program Files\\RyzenAI') || scan(join(HERE, 'ryzenai'));
}
const ryzenai = findRyzenAI();

// ─── XRT-direct backend (yak_xrt_shim.dll → xrt_coreutil.dll → XDNA) ────────
// The honesty top tier on Windows: our own IRON-compiled xclbin executed
// through the C++ register_xclbin path — the same bytes the Linux
// MLIR_AIE/rust-embed path runs, so a claim from either OS verifies
// identically. Artifacts ship in tools/npu-prover/xrt/ (manifest-hashed):
//   yak_xrt_shim.dll — C facade over xrt::device/hw_context/kernel/bo/run
//   final.xclbin     — IRON-compiled gemm64 bf16 (MLIR_AIE kernel)
//   insts.bin        — AIE2 instruction stream (opcode-3 dispatch contract)

function findXrt() {
  const shim = process.env.YAK_XRT_SHIM || join(HERE, 'xrt', 'yak_xrt_shim.dll');
  const xclbin = process.env.YAK_XRT_XCLBIN || join(HERE, 'xrt', 'final.xclbin');
  const insts = process.env.YAK_XRT_INSTS || join(HERE, 'xrt', 'insts.bin');
  return [shim, xclbin, insts].every((p) => existsSync(p))
    ? { shim, xclbin, insts } : null;
}
const xrtFiles = findXrt();

class Xrt {
  constructor(files) {
    this.lib = koffi.load(files.shim);
    this.err = this.lib.func('str yak_last_error()');
    this.deviceOpen = this.lib.func('void *yak_device_open(uint32 index)');
    this.kernelLoad = this.lib.func('void *yak_kernel_load(void *dev, str xclbin, str name)');
    this.groupId = this.lib.func('int yak_kernel_group_id(void *kern, int arg)');
    this.boAlloc = this.lib.func('void *yak_bo_alloc(void *dev, size_t n, int flag, int gid)');
    this.boWrite = this.lib.func('int yak_bo_write(void *bo, void *src, size_t n, size_t off)');
    this.boRead = this.lib.func('int yak_bo_read(void *bo, void *dst, size_t n, size_t off)');
    this.boSyncTo = this.lib.func('int yak_bo_sync_to_device(void *bo)');
    this.boSyncFrom = this.lib.func('int yak_bo_sync_from_device(void *bo)');
    this.runKernel = this.lib.func('int yak_run_kernel(void *kern, uint32 opcode, void *instr, size_t ninstr, void **data, size_t ndata)');
    this.dev = null; this.kern = null; this.bos = null;
  }

  lastError() { try { return this.err() || ''; } catch { return ''; } }

  init(files) {
    this.dev = this.deviceOpen(0);
    if (!this.dev) throw new Error(`yak_device_open: ${this.lastError() || 'no device'}`);
    this.kern = this.kernelLoad(this.dev, files.xclbin, 'MLIR_AIE');
    if (!this.kern) throw new Error(`yak_kernel_load: ${this.lastError() || 'register_xclbin/context/kernel failed'}`);
    const gidI = this.groupId(this.kern, 1);
    const gidD = this.groupId(this.kern, 3);
    const insts = readFileSync(files.insts);
    const instr = this.boAlloc(this.dev, insts.length, 1, gidI);      // 1 = cacheable
    const bos = [0, 1, 2].map(() => this.boAlloc(this.dev, ELEMS * 2, 2, gidD)); // 2 = host_only
    if (!instr || bos.some((b) => !b)) throw new Error(`bo_alloc: ${this.lastError() || 'failed'}`);
    this.boWrite(instr, insts, insts.length, 0);
    this.boSyncTo(instr);
    this.bos = { instr, a: bos[0], b: bos[1], c: bos[2] };
    this.instrBytes = insts.length;
    this.warm(); // one real dispatch — cascade out if it can't execute
  }

  warm() {
    this.boWrite(this.bos.a, Buffer.alloc(ELEMS * 2), ELEMS * 2, 0);
    this.boWrite(this.bos.b, Buffer.alloc(ELEMS * 2), ELEMS * 2, 0);
    this.boWrite(this.bos.c, Buffer.alloc(ELEMS * 2), ELEMS * 2, 0);
    this.boSyncTo(this.bos.a); this.boSyncTo(this.bos.b); this.boSyncTo(this.bos.c);
    const rc = this.runKernel(this.kern, 3, this.bos.instr, this.instrBytes,
      [this.bos.a, this.bos.b, this.bos.c], 3);
    if (rc !== 0) throw new Error(`yak_run_kernel rc=${rc}: ${this.lastError()}`);
    this.boSyncFrom(this.bos.c);
  }

  // One real gemm64 dispatch — bf16 bits in Uint16Array containers.
  run(a16, b16) {
    const { bos } = this;
    this.boWrite(bos.a, Buffer.from(a16.buffer, a16.byteOffset, a16.byteLength), a16.byteLength, 0);
    this.boWrite(bos.b, Buffer.from(b16.buffer, b16.byteOffset, b16.byteLength), b16.byteLength, 0);
    this.boSyncTo(bos.a); this.boSyncTo(bos.b);
    const rc = this.runKernel(this.kern, 3, bos.instr, this.instrBytes, [bos.a, bos.b, bos.c], 3);
    if (rc !== 0) throw new Error(`yak_run_kernel rc=${rc}: ${this.lastError()}`);
    this.boSyncFrom(bos.c);
    const out = Buffer.alloc(ELEMS * 2);
    this.boRead(bos.c, out, ELEMS * 2, 0);
    return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
  }
}

// ─── pure-JS fallback (honest floor tier) ────────────────────────────────────

function jsGemm64(a16, b16, fromBits = f16to32, toBits = f32to16) {
  // fp32-accumulate MatMul — matches the ONNX graph semantics.
  const A = new Float32Array(ELEMS), B = new Float32Array(ELEMS);
  for (let i = 0; i < ELEMS; i++) { A[i] = fromBits(a16[i]); B[i] = fromBits(b16[i]); }
  const out = new Uint16Array(ELEMS);
  for (let i = 0; i < DIM; i++) {
    for (let j = 0; j < DIM; j++) {
      let acc = 0;
      for (let k = 0; k < DIM; k++) acc += A[i * DIM + k] * B[k * DIM + j];
      out[i * DIM + j] = toBits(acc);
    }
  }
  return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
}

// ─── session cascade ─────────────────────────────────────────────────────────

let backend = null;       // 'xrt-npu' | 'vitis-npu' | 'dml-npu' | 'dml-gpu' | 'ort-cpu' | 'js-cpu'
let ort = null;
let sess = null;
let xrt = null;           // Xrt instance when backend === 'xrt-npu'
let onnxType = 10;        // 10 = fp16, 4 = uint16/bf16 (QDQ), 2 = uint8 (QDQ), 1 = fp32
let ortError = null;
const orts = new Map();   // dllPath -> Ort (kept alive for process lifetime)

// PROVER_PROBE=vitis → probe-child mode: run only the vitis attempts, then
// exit 0/1. A native fault (FlexMLRT hw-context failure throws a C++
// exception koffi cannot catch) kills the child, not the server — the
// parent only attempts vitis in-process if the child survived.
const PROBE = process.env.PROVER_PROBE;
const SELF = fileURLToPath(import.meta.url);
function vitisProbe() {
  try {
    const r = spawnSync(process.execPath, [SELF], {
      env: { ...process.env, PROVER_PROBE: 'vitis' },
      timeout: 180000, stdio: 'inherit',   // child's ORT/vaip logs reach prover.log
    });
    return r.status === 0;
  } catch { return false; }
}
// Same crash-isolation for xrt: the shim catches C++ exceptions, but a
// wedged driver/xclbin combo could fault natively — probe in a child first.
function xrtProbe() {
  try {
    const r = spawnSync(process.execPath, [SELF], {
      env: { ...process.env, PROVER_PROBE: 'xrt' },
      timeout: 60000, stdio: 'inherit',
    });
    return r.status === 0;
  } catch { return false; }
}

function ortFor(dll) {
  if (!orts.has(dll)) orts.set(dll, new Ort(dll));
  return orts.get(dll);
}

async function initBackend() {
  if (!koffi) { backend = 'js-cpu'; ortError = `koffi unavailable: ${koffiError}`; return; }
  initProtos();
  const dll = findOrtDll();
  const errs = [];
  if (!dll) errs.push('onnxruntime.dll not found (searched ORT_DLL, tools/npu-prover, node_modules)');

  // Provider dlls (DirectML.dll, onnxruntime_providers_*.dll) resolve via
  // LoadLibrary → exe dir + PATH, NOT the dir of the loaded onnxruntime.dll.
  // Put our bundled bin/ and the RyzenAI deployment dir on PATH (Windows
  // only; on Linux existsSync fails and these are skipped).
  for (const d of [join(HERE, 'bin'), ryzenai?.deployDir].filter(Boolean)) {
    if (existsSync(d) && !(process.env.PATH || '').includes(d)) {
      process.env.PATH = `${d};${process.env.PATH || ''}`;
    }
  }

  // [label, dll|null=findOrtDll(), ep, provider_opts, model, onnx_type]
  const attempts = [];

  // Tier 0 — XRT-direct on our own IRON xclbin. Shim Catches C++ errors
  // itself; the child probe guards against native (driver-level) faults.
  // Probe modes isolate their own tier only.
  if (xrtFiles && (!PROBE || PROBE === 'xrt')) {
    const xrtOk = PROBE === 'xrt' || xrtProbe();
    if (xrtOk) {
      log(`init: trying xrt-npu (shim=${xrtFiles.shim})`);
      try {
        const x = new Xrt(xrtFiles);
        x.init(xrtFiles);
        xrt = x;
        backend = 'xrt-npu';
        onnxType = 4; // uint16 containers carrying bf16 — same as QDQ plumbing
        ortError = errs.length ? errs.join(' | ') : null;
        return;
      } catch (e) { errs.push(`xrt-npu: ${e.message}`); }
    } else {
      errs.push('xrt-npu: probe child crashed or timed out — skipping');
    }
  } else if (PROBE === 'xrt') {
    errs.push('xrt-npu: xrt/ artifacts missing (need yak_xrt_shim.dll + final.xclbin + insts.bin)');
  }

  if (ryzenai?.cfg) {
    // Probe mode runs the vitis attempts itself; the parent probes first
    // because a native fault here kills the process (can't catch C++
    // exceptions through koffi).
    const vitisOk = PROBE === 'vitis' || vitisProbe();
    if (vitisOk) {
      // Real XDNA execution provider. AMD docs: Phoenix/Hawk Point →
      // target 'X1' (fuse_DPU xcompiler path); the config default X2 is
      // Strix. Try X1 first on both models, then the default target.
      attempts.push(['vitis-npu', ryzenai.dll, 'VitisAI', { config_file: ryzenai.cfg, target: 'X1' }, MODEL_FP16, 10]);
      attempts.push(['vitis-npu', ryzenai.dll, 'VitisAI', { config_file: ryzenai.cfg, target: 'X1' }, MODEL_QDQ8, 2]);
      attempts.push(['vitis-npu', ryzenai.dll, 'VitisAI', { config_file: ryzenai.cfg, target: 'X1' }, MODEL_QDQ, 4]);
      attempts.push(['vitis-npu', ryzenai.dll, 'VitisAI', { config_file: ryzenai.cfg }, MODEL_QDQ, 4]);
      // Also try under our own ort dll — may work if bridge versions match.
      attempts.push(['vitis-npu', null, 'VitisAI', { config_file: ryzenai.cfg }, MODEL_FP16, 10]);
    } else {
      errs.push('vitis-npu: probe child crashed or timed out — skipping (native fault, see ORT log lines above)');
    }
  }
  attempts.push(
    ['dml-npu', null, 'DML', { device_filter: 'npu' }, MODEL_FP16, 10],
    ['dml-npu', null, 'DML', { device_filter: 'npu' }, MODEL_FP32, 1],
    ['dml-gpu', null, 'DML', { device_filter: 'gpu' }, MODEL_FP16, 10],
    ['ort-cpu', null, null, null, MODEL_FP16, 10],
    ['ort-cpu', null, null, null, MODEL_FP32, 1],
  );

  const wanted = PROBE === 'vitis' ? attempts.filter(([l]) => l === 'vitis-npu')
    : PROBE === 'xrt' ? []   // xrt was attempted inline above
    : attempts;
  for (const [label, d, ep, opts, model, otype] of wanted) {
    const dllPath = d || dll;
    if (!dllPath) continue;
    log(`init: trying ${label} (dll=${dllPath} ep=${ep || 'cpu'} type=${otype})`);
    try {
      const o = ortFor(dllPath);
      sess = o.createSession(model, ep, opts, otype);
      // Warm up with one real dispatch — a backend that can't execute
      // (e.g. NPU driver without fp16 MatMul) cascades to the next tier.
      o.warm(sess);
      ort = o;
      backend = label;
      onnxType = otype;
      // Failed higher tiers are diagnostic — expose them in /health.
      ortError = errs.length ? errs.join(' | ') : null;
      return;
    } catch (e) { errs.push(`${label}: ${e.message}`); }
  }
  ortError = errs.join(' | ') || null;
  ort = null;
  backend = 'js-cpu';
}

// ─── proof ───────────────────────────────────────────────────────────────────

log('init: probing pnp');
const device = PROBE ? { generation: 'probe' } : probeDevice();
log('init: enumerating dxcore');
const dxAdapters = PROBE ? [] : enumDxCore();
const npuAdapter = dxAdapters.find((a) => a.is_npu) || null;
log(`init: probes done (${dxAdapters.length} dxcore adapters)`);

// The proof's `device` must name the silicon that EXECUTED the kernel —
// the claim says WHAT ran, not what exists. On non-NPU backends the PnP
// NPU's PCI id would overstate; NPU presence stays disclosed separately
// via `adapter`/`adapters`/`device.pnp` regardless of executor.
function execDevice() {
  if (backend === 'xrt-npu' || backend === 'vitis-npu' || backend === 'dml-npu')
    return backend === 'xrt-npu' ? { ...device, generation: 'windows/xrt' } : device;
  if (backend === 'dml-gpu') {
    const g = dxAdapters.find((a) => a.is_hardware && !a.is_npu)
      || dxAdapters.find((a) => a.is_hardware) || null;
    return {
      generation: 'windows/onnxruntime',
      pci: (g?.vendor_id && g?.device_id)
        ? `${g.vendor_id}:${g.device_id}`.replace(/0x/gi, '').toLowerCase() : null,
      pnp: null, name: g?.desc || 'DirectML GPU', luid: g?.luid || null,
      npuPresent: device?.pci || null,
    };
  }
  return { generation: backend === 'js-cpu' ? 'js/no-ort' : 'cpu',
    pci: null, pnp: null, name: 'host CPU', npuPresent: device?.pci || null };
}

async function runProof(n, nonce) {
  const rng = xorshift64star(seedFromNonce(nonce));
  // onnxType 4 (uint16) carries bf16 bits — the QDQ model path.
  // onnxType 2 (uint8) is the real-quantized QDQ path: inputs quantized to
  // {0,1} at scale 1 zp 0 — dot product ≤ 64, no output clipping.
  const toBits = onnxType === 4 ? f32tobf16 : onnxType === 2 ? (v) => (v >= 0 ? 1 : 0) : f32to16;
  const fromBits = onnxType === 4 ? bf16to32 : f16to32;
  const A = onnxType === 2 ? new Uint8Array(ELEMS) : new Uint16Array(ELEMS);
  const B = onnxType === 2 ? new Uint8Array(ELEMS) : new Uint16Array(ELEMS);
  for (let i = 0; i < ELEMS; i++) {
    A[i] = toBits((Number(rng() % 4096n) / 1024) - 2);
    B[i] = toBits((Number(rng() % 4096n) / 1024) - 2);
  }
  const inputDigest = fnv1a64(Buffer.concat([
    Buffer.from(A.buffer, A.byteOffset, A.byteLength),
    Buffer.from(B.buffer, B.byteOffset, B.byteLength),
  ]));

  const times = [];
  const outputDigests = new Set();
  let lastOutput = null;

  if (backend === 'js-cpu') {
    for (let i = 0; i < n; i++) {
      const t0 = performance.now();
      lastOutput = jsGemm64(A, B, fromBits, toBits);
      times.push((performance.now() - t0) * 1e6);
      outputDigests.add(fnv1a64(Buffer.from(lastOutput)));
    }
  } else if (backend === 'xrt-npu') {
    // Persistent BOs — write A/B, opcode-3 dispatch, read C. A and B are
    // Uint16Array carrying bf16 bits (the kernel's native format).
    for (let i = 0; i < n; i++) {
      const t0 = performance.now();
      lastOutput = xrt.run(A, B);
      times.push((performance.now() - t0) * 1e6);
      outputDigests.add(fnv1a64(Buffer.from(lastOutput)));
    }
  } else {
    let tA, tB;
    if (onnxType === 1) {
      // fp32 model — widen the fp16 inputs (same values, wider dtype)
      const Af = new Float32Array(ELEMS), Bf = new Float32Array(ELEMS);
      for (let i = 0; i < ELEMS; i++) { Af[i] = f16to32(A[i]); Bf[i] = f16to32(B[i]); }
      tA = Af; tB = Bf;
    } else {
      tA = A; tB = B;
    }
    const inA = ort.makeTensor(tA, onnxType);
    const inB = ort.makeTensor(tB, onnxType);
    for (let i = 0; i < n; i++) {
      const t0 = performance.now();
      lastOutput = ort.run(sess, [inA, inB]);
      times.push((performance.now() - t0) * 1e6);
      outputDigests.add(fnv1a64(Buffer.from(lastOutput)));
    }
    koffi.call(ort.api[API.ReleaseValue], P.ReleaseObj, inA);
    koffi.call(ort.api[API.ReleaseValue], P.ReleaseObj, inB);
  }

  const sorted = [...times].sort((a, b) => a - b);
  const q = (p) => sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))];
  const mean = times.reduce((a, b) => a + b, 0) / times.length;

  return {
    status: 'ok',
    proof_of: 'execution',
    device: execDevice(),
    backend,
    adapter: npuAdapter || undefined,
    adapters: dxAdapters.length ? dxAdapters : undefined,
    kernel: backend === 'xrt-npu' ? 'xrt-npu gemm64 (bf16)'
      : `${backend} gemm64 (${{ 1: 'fp32', 2: 'qdq-u8', 4: 'qdq-bf16' }[onnxType] || 'fp16'})`,
    ort_version: ort?.version || undefined,
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

// ─── http ────────────────────────────────────────────────────────────────────

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
      .end(JSON.stringify({ status: 'ok', backend, device, adapter: npuAdapter,
        ort_version: ort?.version, ort_error: ortError,
        xrt_shim: xrt ? xrtFiles.shim : undefined }));
  } else {
    res.writeHead(404).end();
  }
});

// A failed init still serves honest js-cpu proofs — never die before listen.
initBackend().catch((e) => {
  ortError = `init: ${e.message || e}`;
  backend = 'js-cpu';
  console.error('[npu-prover] init failed (js-cpu fallback):', e);
}).then(() => {
  if (PROBE) {
    log(`probe result: backend=${backend} — ${backend === 'js-cpu' ? 'FAIL' : 'OK'}`);
    process.exit(backend === 'js-cpu' ? 1 : 0);
  }
  server.listen(PORT, '127.0.0.1', () => {
    // Claim the bound port — yakos-verifyd aggregates ports.d/* into
    // the merged registry and audits ownership (no claim = squatter).
    import('../../utils/ports.js')
      .then((p) => { if (!p.rememberPort('yakmesh-npu-prover', PORT)) log('warn: could not claim port in ports.d/'); })
      .catch(() => { /* no registry on this host */ });
    log(`backend=${backend}${onnxType === 1 ? ' (fp32)' : ''} — listening on http://127.0.0.1:${PORT}/npu/proof`);
    log(`ort=${ort?.version || 'unavailable'}${ortError ? ' err=' + ortError : ''}`);
    log(`pnp: ${device.name || 'unidentified'} (${device.pnp || 'no pnp id'})`);
    if (npuAdapter) {
      log(`npu adapter: ${npuAdapter.desc} luid=${npuAdapter.luid} drv=${npuAdapter.driver_version}`);
    } else {
      log(`npu adapter: none in DXCore list (${dxAdapters.length} adapters)`);
    }
  });
});
