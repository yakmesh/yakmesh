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
