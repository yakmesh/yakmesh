#!/usr/bin/env node
/*
 * Generate gemm64-fp16.onnx — a minimal single-MatMul ONNX model used by
 * the Windows execution prover. Hand-encoded protobuf (no onnx package
 * needed): ModelProto{ ir_version=8, opset 13, graph{ MatMul A,B→C } }
 * with all tensors fp16 [64,64].
 *
 *   node tools/npu-prover/gen-model.mjs
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const varint = (n) => {
  const out = [];
  n = BigInt(n);
  do { let b = Number(n & 0x7fn); n >>= 7n; if (n) b |= 0x80; out.push(b); } while (n);
  return Buffer.from(out);
};
const tag = (f, w) => varint((f << 3) | w);
const lenDelim = (f, buf) => Buffer.concat([tag(f, 2), varint(buf.length), buf]);
const varintField = (f, v) => Buffer.concat([tag(f, 0), varint(v)]);
const str = (f, s) => lenDelim(f, Buffer.from(s, 'utf8'));

const FP16 = 10; // TensorProto.DataType.FLOAT16
const D = 64;

// TensorShapeProto{ dim: [dim_value=D, dim_value=D] }
const dim = (v) => lenDelim(1, varintField(1, v));
const shape = Buffer.concat([dim(D), dim(D)]);
// TypeProto{ tensor_type{ elem_type: FP16, shape } }
const tensorType = lenDelim(1, Buffer.concat([varintField(1, FP16), lenDelim(2, shape)]));
// ValueInfoProto{ name, type }
const valueInfo = (name) => Buffer.concat([str(1, name), lenDelim(2, tensorType)]);

// NodeProto{ input:[A,B], output:[C], op_type:"MatMul" }
const node = Buffer.concat([str(1, 'A'), str(1, 'B'), str(2, 'C'), str(4, 'MatMul')]);

// GraphProto{ node, name, input:[A,B], output:[C] }
const graph = Buffer.concat([
  lenDelim(1, node),
  str(2, 'yakmesh-gemm64-fp16'),
  lenDelim(11, valueInfo('A')),
  lenDelim(11, valueInfo('B')),
  lenDelim(12, valueInfo('C')),
]);

// OperatorSetIdProto{ version: 13 }  (default domain — field 1 omitted)
const opset = varintField(2, 13);

// ModelProto{ ir_version: 8, graph (field 7), opset_import (field 8) }
const model = Buffer.concat([
  varintField(1, 8),
  lenDelim(7, graph),
  lenDelim(8, opset),
]);

const out = join(dirname(fileURLToPath(import.meta.url)), 'gemm64-fp16.onnx');
writeFileSync(out, model);
console.log(`wrote ${out} (${model.length} bytes)`);

// ─── QDQ bf16 variant (gemm64-qdq.onnx) ──────────────────────────────────────
// vaip only fuses QDQ-wrapped MatMul (m_qmatmul_act_act → QMatMulDynamic).
// Boundary tensors are uint16 carrying bf16 bits: scale bf16=1.0, zp u16=0.
// opset 21 (uint16 Q/DQ). No CPU kernel — vitis-tier only.
const U16 = 4, F32 = 1;
const ttype2 = (t) => lenDelim(1, Buffer.concat([varintField(1, t), lenDelim(2, shape)]));
const vi2 = (name, t) => Buffer.concat([str(1, name), lenDelim(2, ttype2(t))]);
const init = (name, dt, bytes) => Buffer.concat([varintField(2, dt), str(8, name), lenDelim(9, bytes)]);
const sF32 = init('s', F32, Buffer.from([0x00, 0x00, 0x80, 0x3f]));   // fp32 1.0 — vaip REQUIRES float32 scales
const zU16 = init('z', U16, Buffer.from([0x00, 0x00]));     // uint16 0
const node2 = (ins, outs, op) => Buffer.concat([
  ...ins.map((i) => str(1, i)), ...outs.map((o) => str(2, o)), str(4, op),
]);
const graph2 = Buffer.concat([
  lenDelim(1, node2(['a', 's', 'z'], ['a_f'], 'DequantizeLinear')),
  lenDelim(1, node2(['b', 's', 'z'], ['b_f'], 'DequantizeLinear')),
  lenDelim(1, node2(['a_f', 'b_f'], ['m_f'], 'MatMul')),
  lenDelim(1, node2(['m_f', 's', 'z'], ['out'], 'QuantizeLinear')),
  str(2, 'yakmesh-gemm64-qdq-bf16'),
  lenDelim(5, sF32), lenDelim(5, zU16),
  lenDelim(11, vi2('a', U16)), lenDelim(11, vi2('b', U16)),
  lenDelim(12, vi2('out', U16)),
]);
const model2 = Buffer.concat([varintField(1, 10), lenDelim(7, graph2), lenDelim(8, varintField(2, 21))]);
const out2 = join(dirname(fileURLToPath(import.meta.url)), 'gemm64-qdq.onnx');
writeFileSync(out2, model2);
console.log(`wrote ${out2} (${model2.length} bytes)`);
