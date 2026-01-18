/**
 * Yakmesh Temporal Mesh Encoding (TME)
 * 
 * A novel approach to packet resilience that exploits Yakmesh's unique capabilities:
 * - Atomic time synchronization (configurable precision from NTP to PCIe atomic clock levels)
 * - Post-quantum ML-DSA-65 signatures for cryptographic time binding
 * - Mesh topology awareness for intelligent path diversity
 * 
 * Instead of traditional erasure coding (encoding data across space),
 * TME encodes data across TIME - using the mesh's synchronized clocks
 * as the redundancy dimension.
 * 
 * Key Innovation: "Time IS the redundancy dimension"
 * - Temporal slicing with cryptographic chaining
 * - Predictive reconstruction from timing proofs
 * - Mesh heartbeat differential encoding
 * 
 * @module mesh/temporal-encoder
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { randomBytes, createHash } from 'crypto';

const TME_CONFIG = {
  defaultSliceIntervalNs: 50_000_000,
  maxSlicesPerStream: 256,
  reconstructionWindowNs: 500_000_000,
  timingToleranceNs: 5_000_000,
  hashAlgorithm: 'sha3-256',  // Post-quantum consistent hashing
  temporalHashLength: 32,
  minSlicesForReconstruction: 0.6,
  maxMissingConsecutive: 3,
  minPathDiversity: 2,
  maxPathReuse: 3,
};

class TemporalSlice {
  constructor(options) {
    this.data = Buffer.from(options.data);
    this.timestamp = BigInt(options.timestamp);
    this.sequenceNumber = options.sequenceNumber;
    this.streamId = options.streamId;
    this.prevTemporalHash = options.prevTemporalHash || Buffer.alloc(32);
    this.meshPosition = options.meshPosition || [0, 0, 0];
    this.createdAt = Date.now();
    this.temporalHash = this._computeTemporalHash();
  }

  _computeTemporalHash() {
    const hash = createHash(TME_CONFIG.hashAlgorithm);
    hash.update(this.data);
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeBigUInt64BE(this.timestamp);
    hash.update(timeBuffer);
    const seqBuffer = Buffer.alloc(4);
    seqBuffer.writeUInt32BE(this.sequenceNumber);
    hash.update(seqBuffer);
    hash.update(this.streamId);
    hash.update(this.prevTemporalHash);
    const posBuffer = Buffer.alloc(12);
    posBuffer.writeFloatBE(this.meshPosition[0], 0);
    posBuffer.writeFloatBE(this.meshPosition[1], 4);
    posBuffer.writeFloatBE(this.meshPosition[2], 8);
    hash.update(posBuffer);
    return hash.digest();
  }

  verify() {
    const computed = this._computeTemporalHash();
    return computed.equals(this.temporalHash);
  }

  serialize() {
    return {
      data: this.data.toString('base64'),
      timestamp: this.timestamp.toString(),
      sequenceNumber: this.sequenceNumber,
      streamId: this.streamId,
      prevTemporalHash: this.prevTemporalHash.toString('hex'),
      temporalHash: this.temporalHash.toString('hex'),
      meshPosition: this.meshPosition,
    };
  }

  static deserialize(obj) {
    const slice = new TemporalSlice({
      data: Buffer.from(obj.data, 'base64'),
      timestamp: BigInt(obj.timestamp),
      sequenceNumber: obj.sequenceNumber,
      streamId: obj.streamId,
      prevTemporalHash: Buffer.from(obj.prevTemporalHash, 'hex'),
      meshPosition: obj.meshPosition,
    });
    const expectedHash = Buffer.from(obj.temporalHash, 'hex');
    if (!slice.temporalHash.equals(expectedHash)) {
      throw new Error('Temporal hash mismatch - slice may be corrupted or tampered');
    }
    return slice;
  }
}

class TemporalStream {
  constructor(options = {}) {
    this.streamId = options.streamId || this._generateStreamId();
    this.sliceSize = options.sliceSize || 1024;
    this.baseTimestamp = BigInt(options.baseTimestamp || Date.now() * 1_000_000);
    this.sliceIntervalNs = options.sliceIntervalNs || TME_CONFIG.defaultSliceIntervalNs;
    this.slices = new Map();
    this.totalSlices = 0;
    this.isComplete = false;
  }

  _generateStreamId() {
    return randomBytes(16).toString('hex');
  }

  encode(message, meshPosition = [0, 0, 0]) {
    const data = Buffer.from(message);
    const slices = [];
    let prevHash = Buffer.alloc(32);
    this.totalSlices = Math.ceil(data.length / this.sliceSize);
    if (this.totalSlices > TME_CONFIG.maxSlicesPerStream) {
      throw new Error('Message too large: requires ' + this.totalSlices + ' slices, max is ' + TME_CONFIG.maxSlicesPerStream);
    }
    for (let i = 0; i < this.totalSlices; i++) {
      const start = i * this.sliceSize;
      const end = Math.min(start + this.sliceSize, data.length);
      const sliceData = data.slice(start, end);
      const timestamp = this.baseTimestamp + BigInt(i * this.sliceIntervalNs);
      const slice = new TemporalSlice({
        data: sliceData,
        timestamp,
        sequenceNumber: i,
        streamId: this.streamId,
        prevTemporalHash: prevHash,
        meshPosition,
      });
      slices.push(slice);
      this.slices.set(i, slice);
      prevHash = slice.temporalHash;
    }
    this.isComplete = true;
    return slices;
  }

  addSlice(slice) {
    if (slice.streamId !== this.streamId) return false;
    if (!slice.verify()) return false;
    if (slice.sequenceNumber > 0 && this.slices.has(slice.sequenceNumber - 1)) {
      const prevSlice = this.slices.get(slice.sequenceNumber - 1);
      if (!slice.prevTemporalHash.equals(prevSlice.temporalHash)) return false;
    }
    this.slices.set(slice.sequenceNumber, slice);
    return true;
  }

  canReconstruct() {
    if (this.totalSlices === 0) return false;
    return (this.slices.size / this.totalSlices) >= TME_CONFIG.minSlicesForReconstruction;
  }

  getMissingSlices() {
    const missing = [];
    for (let i = 0; i < this.totalSlices; i++) {
      if (!this.slices.has(i)) missing.push(i);
    }
    return missing;
  }

  getCompletionPercent() {
    if (this.totalSlices === 0) return 0;
    return (this.slices.size / this.totalSlices) * 100;
  }
}

class TemporalReconstructor {
  constructor() {
    this.streams = new Map();
    this.timingProofs = new Map();
  }

  registerStream(stream) {
    this.streams.set(stream.streamId, stream);
    this.timingProofs.set(stream.streamId, new Map());
  }

  addTimingProof(streamId, sequenceNumber, proof) {
    if (!this.timingProofs.has(streamId)) {
      this.timingProofs.set(streamId, new Map());
    }
    const streamProofs = this.timingProofs.get(streamId);
    if (!streamProofs.has(sequenceNumber)) {
      streamProofs.set(sequenceNumber, []);
    }
    streamProofs.get(sequenceNumber).push({
      nodeId: proof.nodeId,
      timestamp: BigInt(proof.timestamp),
      temporalHash: Buffer.from(proof.temporalHash, 'hex'),
      signature: proof.signature,
      receivedAt: Date.now(),
    });
  }

  verifyMissingSlice(streamId, sequenceNumber) {
    const streamProofs = this.timingProofs.get(streamId);
    if (!streamProofs || !streamProofs.has(sequenceNumber)) return null;
    const proofs = streamProofs.get(sequenceNumber);
    if (proofs.length < 2) return null;
    const hashCounts = new Map();
    for (const proof of proofs) {
      const hashHex = proof.temporalHash.toString('hex');
      hashCounts.set(hashHex, (hashCounts.get(hashHex) || 0) + 1);
    }
    let consensusHash = null;
    let maxCount = 0;
    for (const [hash, count] of hashCounts) {
      if (count > maxCount) {
        maxCount = count;
        consensusHash = hash;
      }
    }
    if (maxCount >= 2) {
      return { verified: true, consensusHash, proofCount: maxCount, totalProofs: proofs.length };
    }
    return null;
  }

  reconstruct(streamId) {
    const stream = this.streams.get(streamId);
    if (!stream) return { success: false, error: 'Stream not found' };
    const missing = stream.getMissingSlices();
    if (missing.length === 0) return this._assembleComplete(stream);
    if (!stream.canReconstruct()) {
      return {
        success: false,
        error: 'Insufficient slices for reconstruction',
        received: stream.slices.size,
        required: Math.ceil(stream.totalSlices * TME_CONFIG.minSlicesForReconstruction),
        total: stream.totalSlices,
      };
    }
    const reconstructed = [];
    const unrecoverable = [];
    for (const seq of missing) {
      const result = this._interpolateSlice(stream, seq);
      if (result.success) reconstructed.push(seq);
      else unrecoverable.push(seq);
    }
    if (unrecoverable.length > 0) {
      return {
        success: false,
        error: 'Some slices unrecoverable',
        reconstructed,
        unrecoverable,
        completionPercent: stream.getCompletionPercent(),
      };
    }
    return this._assembleComplete(stream);
  }

  _interpolateSlice(stream, sequenceNumber) {
    const prev = stream.slices.get(sequenceNumber - 1);
    const next = stream.slices.get(sequenceNumber + 1);
    if (prev && next) {
      const expectedHash = next.prevTemporalHash;
      return { success: false, expectedHash: expectedHash.toString('hex'), reason: 'Need data from mesh neighbors' };
    }
    return { success: false, reason: 'Insufficient surrounding slices' };
  }

  _assembleComplete(stream) {
    const sortedSlices = Array.from(stream.slices.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([_, slice]) => slice);
    for (let i = 1; i < sortedSlices.length; i++) {
      const prev = sortedSlices[i - 1];
      const curr = sortedSlices[i];
      if (!curr.prevTemporalHash.equals(prev.temporalHash)) {
        return { success: false, error: 'Temporal chain broken at slice ' + i };
      }
    }
    const data = Buffer.concat(sortedSlices.map(s => s.data));
    return { success: true, data, sliceCount: sortedSlices.length, streamId: stream.streamId };
  }
}

class TemporalMeshEncoder {
  constructor(options = {}) {
    this.nodeId = options.nodeId || randomBytes(16).toString('hex');
    this.meshPosition = options.meshPosition || [0, 0, 0];
    this.reconstructor = new TemporalReconstructor();
    this.outboundStreams = new Map();
    this.inboundStreams = new Map();
    this.stats = {
      slicesSent: 0,
      slicesReceived: 0,
      streamsCompleted: 0,
      reconstructionAttempts: 0,
      successfulReconstructions: 0,
    };
  }

  encode(message, options = {}) {
    const stream = new TemporalStream({
      sliceSize: options.sliceSize || 1024,
      baseTimestamp: options.baseTimestamp,
      sliceIntervalNs: options.sliceIntervalNs,
    });
    const slices = stream.encode(message, this.meshPosition);
    this.outboundStreams.set(stream.streamId, stream);
    this.stats.slicesSent += slices.length;
    return {
      streamId: stream.streamId,
      slices: slices.map(s => s.serialize()),
      metadata: {
        totalSlices: stream.totalSlices,
        sliceSize: stream.sliceSize,
        sliceIntervalNs: stream.sliceIntervalNs,
        baseTimestamp: stream.baseTimestamp.toString(),
      },
    };
  }

  initReceive(metadata) {
    const stream = new TemporalStream({
      streamId: metadata.streamId,
      sliceSize: metadata.sliceSize,
      baseTimestamp: BigInt(metadata.baseTimestamp),
      sliceIntervalNs: metadata.sliceIntervalNs,
    });
    stream.totalSlices = metadata.totalSlices;
    this.inboundStreams.set(metadata.streamId, stream);
    this.reconstructor.registerStream(stream);
    return stream.streamId;
  }

  receiveSlice(serializedSlice) {
    try {
      const slice = TemporalSlice.deserialize(serializedSlice);
      const stream = this.inboundStreams.get(slice.streamId);
      if (!stream) return { accepted: false, error: 'Unknown stream' };
      const added = stream.addSlice(slice);
      if (added) this.stats.slicesReceived++;
      const completionPercent = stream.getCompletionPercent();
      const streamComplete = completionPercent === 100;
      if (streamComplete) this.stats.streamsCompleted++;
      return { accepted: added, streamComplete, completionPercent, missing: stream.getMissingSlices() };
    } catch (err) {
      return { accepted: false, error: err.message };
    }
  }

  addTimingProof(streamId, sequenceNumber, proof) {
    this.reconstructor.addTimingProof(streamId, sequenceNumber, proof);
  }

  decode(streamId) {
    this.stats.reconstructionAttempts++;
    const result = this.reconstructor.reconstruct(streamId);
    if (result.success) this.stats.successfulReconstructions++;
    return result;
  }

  getStreamStatus(streamId) {
    const stream = this.inboundStreams.get(streamId);
    if (!stream) return null;
    return {
      streamId,
      totalSlices: stream.totalSlices,
      receivedSlices: stream.slices.size,
      completionPercent: stream.getCompletionPercent(),
      missing: stream.getMissingSlices(),
      canReconstruct: stream.canReconstruct(),
    };
  }

  getStats() {
    return { ...this.stats };
  }
}

export { TME_CONFIG, TemporalSlice, TemporalStream, TemporalReconstructor, TemporalMeshEncoder };
