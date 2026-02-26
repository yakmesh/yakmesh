/**
 * TERNARY-ML — Balanced Ternary Quantization for ML Inference
 * 
 * Bridges TRIBHUJ balanced ternary algebra with ONNX ML inference via
 * the ACCEL hardware acceleration layer. Provides:
 * 
 * 1. Ternary quantization of float features → {-1, 0, +1} trits
 * 2. SST family-aware feature encoding (digital root → family → trit)
 * 3. TernaryInferenceAdapter for routing ternary-quantized data through NPU/GPU
 * 4. Trust-aware consensus scoring using ternary majority logic
 * 
 * Why ternary quantization for YAKMESH ML?
 * - AMD XDNA NPU operates on INT8 but ternary {-1,0,+1} maps directly to it
 * - Reduces feature space from float32 to 2 bits (ternary) per feature
 * - Natural alignment with KARMA trust scores (DISTRUST/UNVERIFIED/TRUST)
 * - SAKSHI anomaly detection benefits from 3-state classification
 * - The 3^N state space prevents gradient-based adversarial attacks
 * 
 * Integration:
 *   TRIBHUJ (algebra) → TERNARY-ML (quantization) → ACCEL (hardware)
 *   SST (family mapping) → TERNARY-ML (feature encoding) → ONNX (inference)
 * 
 * @module oracle/ternary-ml
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { Trit, TritArray, POSITIVE, NEUTRAL, NEGATIVE, TritState } from './tribhuj.js';
import { toFamilyTrit, getFamilyOf, SSTFamily, digitalRoot } from './sst.js';

// =============================================================================
// TERNARY QUANTIZATION
// =============================================================================

/**
 * Quantize a float value to a balanced trit {-1, 0, +1}.
 * 
 * Uses a dead-zone around zero to prevent noise from creating false signals:
 *   value < -threshold → NEGATIVE (-1)
 *   -threshold ≤ value ≤ +threshold → NEUTRAL (0)
 *   value > +threshold → POSITIVE (+1)
 * 
 * @param {number} value — float value to quantize
 * @param {number} [threshold=0.33] — dead-zone radius
 * @returns {number} — trit value {-1, 0, +1}
 */
export function quantizeToTrit(value, threshold = 0.33) {
  if (value < -threshold) return NEGATIVE;
  if (value > threshold) return POSITIVE;
  return NEUTRAL;
}

/**
 * Quantize a float array to balanced trits.
 * 
 * @param {Float32Array | number[]} values — float values
 * @param {number} [threshold=0.33] — dead-zone radius
 * @returns {Int8Array} — trit values
 */
export function quantizeArray(values, threshold = 0.33) {
  const trits = new Int8Array(values.length);
  for (let i = 0; i < values.length; i++) {
    trits[i] = quantizeToTrit(values[i], threshold);
  }
  return trits;
}

/**
 * Adaptive quantization — threshold derived from data statistics.
 * 
 * Computes mean and standard deviation, then uses:
 *   threshold = max(minThreshold, sigma * factor)
 * 
 * This prevents the dead-zone from being too narrow (noise)
 * or too wide (losing signal).
 * 
 * @param {Float32Array | number[]} values 
 * @param {number} [factor=0.5] — sigma multiplier
 * @param {number} [minThreshold=0.1] — absolute minimum
 * @returns {{ trits: Int8Array, threshold: number, mean: number, sigma: number }}
 */
export function adaptiveQuantize(values, factor = 0.5, minThreshold = 0.1) {
  const n = values.length;
  if (n === 0) return { trits: new Int8Array(0), threshold: 0, mean: 0, sigma: 0 };
  
  // Compute mean
  let sum = 0;
  for (let i = 0; i < n; i++) sum += values[i];
  const mean = sum / n;
  
  // Compute standard deviation
  let sqDiffSum = 0;
  for (let i = 0; i < n; i++) {
    const diff = values[i] - mean;
    sqDiffSum += diff * diff;
  }
  const sigma = Math.sqrt(sqDiffSum / n);
  
  // Adaptive threshold
  const threshold = Math.max(minThreshold, sigma * factor);
  
  // Center and quantize
  const trits = new Int8Array(n);
  for (let i = 0; i < n; i++) {
    trits[i] = quantizeToTrit(values[i] - mean, threshold);
  }
  
  return { trits, threshold, mean, sigma };
}

/**
 * Dequantize trits back to float approximation.
 * Uses mean and threshold from the quantization step.
 * 
 * @param {Int8Array} trits 
 * @param {number} mean — original mean
 * @param {number} threshold — quantization threshold
 * @returns {Float32Array} — reconstructed approximation
 */
export function dequantizeTrits(trits, mean = 0, threshold = 0.33) {
  const values = new Float32Array(trits.length);
  for (let i = 0; i < trits.length; i++) {
    values[i] = mean + trits[i] * threshold;
  }
  return values;
}

// =============================================================================
// SST FAMILY FEATURE ENCODING
// =============================================================================

/**
 * Encode numeric features using SST family classification.
 * 
 * Each feature value is mapped through:
 *   value → digitalRoot → family → trit
 * 
 * This creates a "harmonic fingerprint" of the feature vector
 * where the 3-6-9 governing family acts as natural clustering.
 * 
 * Use cases:
 * - Node ID classification for routing
 * - Trust score family grouping
 * - Anomaly detection (unusual family distribution)
 * 
 * @param {number[]} features — numeric feature values (integers)
 * @returns {{ trits: Int8Array, families: string[], roots: number[] }}
 */
export function sstEncodeFeatures(features) {
  const n = features.length;
  const trits = new Int8Array(n);
  const families = new Array(n);
  const roots = new Array(n);
  
  for (let i = 0; i < n; i++) {
    const val = Math.abs(Math.floor(features[i]));
    roots[i] = digitalRoot(val);
    families[i] = getFamilyOf(val);
    trits[i] = toFamilyTrit(val).value;
  }
  
  return { trits, families, roots };
}

/**
 * Compute the family balance of encoded features.
 * A balanced distribution (roughly equal A, B, C) indicates
 * normal/healthy data. Skew indicates anomaly.
 * 
 * @param {string[]} families — array of 'A', 'B', 'C' 
 * @returns {{ a: number, b: number, c: number, balance: number, isBalanced: boolean }}
 */
export function familyBalance(families) {
  let a = 0, b = 0, c = 0;
  for (const f of families) {
    if (f === SSTFamily.A) a++;
    else if (f === SSTFamily.B) b++;
    else c++;
  }
  
  const n = families.length || 1;
  const expected = n / 3;
  
  // Chi-squared-like balance metric (0 = perfect balance, higher = more skewed)
  const balance = Math.sqrt(
    Math.pow(a - expected, 2) + 
    Math.pow(b - expected, 2) + 
    Math.pow(c - expected, 2)
  ) / expected;
  
  return {
    a, b, c,
    balance: +balance.toFixed(4),
    isBalanced: balance < 1.0, // Within 1 standard deviation
  };
}

// =============================================================================
// TERNARY FEATURE VECTOR (for ONNX model input)
// =============================================================================

/**
 * Build a ternary feature vector suitable for ONNX model input.
 * 
 * Packs multiple signal channels into a single vector:
 * 1. Adaptive-quantized raw features (captures signal direction)
 * 2. SST family encoding (captures harmonic structure)
 * 3. Family balance metrics (captures distribution health)
 * 
 * The result is a Float32Array ready for ONNX Tensor creation.
 * Values are in {-1, 0, +1} but typed as float32 for ONNX compatibility.
 * 
 * @param {Float32Array | number[]} rawFeatures — original float features
 * @param {Object} [options]
 * @param {number} [options.quantThreshold=0.33] — fixed threshold (0 = adaptive)
 * @param {boolean} [options.includeSST=true] — include SST family channel
 * @param {boolean} [options.includeBalance=true] — include balance metrics
 * @returns {{ vector: Float32Array, channels: Object, dimensions: number }}
 */
export function buildTernaryFeatureVector(rawFeatures, options = {}) {
  const { 
    quantThreshold = 0, // 0 means adaptive
    includeSST = true,
    includeBalance = true,
  } = options;
  
  // Channel 1: Adaptive quantization of raw float features
  const quant = quantThreshold > 0
    ? { trits: quantizeArray(rawFeatures, quantThreshold), threshold: quantThreshold, mean: 0, sigma: 0 }
    : adaptiveQuantize(rawFeatures);
  
  // Channel 2: SST family encoding (if features are interpretable as integers)
  let sstTrits = null;
  let balance = null;
  if (includeSST) {
    const encoded = sstEncodeFeatures(Array.from(rawFeatures).map(v => Math.round(Math.abs(v * 1000))));
    sstTrits = encoded.trits;
    if (includeBalance) {
      balance = familyBalance(encoded.families);
    }
  }
  
  // Assemble the vector
  const channels = {
    quantized: quant.trits,
    sst: sstTrits,
    balance,
  };
  
  // Calculate total dimensions
  let dimensions = quant.trits.length;
  if (sstTrits) dimensions += sstTrits.length;
  if (balance) dimensions += 3; // a_ratio, b_ratio, c_ratio as trits
  
  // Pack into Float32Array for ONNX compatibility
  const vector = new Float32Array(dimensions);
  let offset = 0;
  
  // Write quantized channel
  for (let i = 0; i < quant.trits.length; i++) {
    vector[offset++] = quant.trits[i];
  }
  
  // Write SST channel
  if (sstTrits) {
    for (let i = 0; i < sstTrits.length; i++) {
      vector[offset++] = sstTrits[i];
    }
  }
  
  // Write balance as ternary indicators
  if (balance) {
    const n = rawFeatures.length || 1;
    vector[offset++] = quantizeToTrit((balance.a / n) - (1/3), 0.1);
    vector[offset++] = quantizeToTrit((balance.b / n) - (1/3), 0.1);
    vector[offset++] = quantizeToTrit((balance.c / n) - (1/3), 0.1);
  }
  
  return { vector, channels, dimensions };
}

// =============================================================================
// TERNARY INFERENCE ADAPTER
// =============================================================================

/**
 * TernaryInferenceAdapter — Routes ternary-quantized features through
 * the ACCEL inference engine (NPU → GPU → CPU).
 * 
 * This adapter sits between the ternary quantization layer and the
 * ONNX models, providing:
 * - Ternary feature encoding
 * - Model-specific input formatting
 * - Output trit classification
 * - Consensus-based multi-model voting
 * 
 * The adapter does NOT load models itself — it delegates to the
 * shared inference engine from accel.js.
 */
export class TernaryInferenceAdapter {
  /**
   * @param {Object} inferenceEngine — accel.inference singleton
   */
  constructor(inferenceEngine) {
    this._engine = inferenceEngine;
    this._stats = {
      totalInferences: 0,
      ternaryInputs: 0,
      consensusVotes: 0,
    };
  }

  /**
   * Run ternary-quantized inference on a named model.
   * 
   * @param {string} modelName — model loaded in inference engine
   * @param {Float32Array | number[]} rawFeatures — raw float features
   * @param {Object} [options]
   * @param {boolean} [options.ternaryOutput=true] — quantize output to trits
   * @param {number} [options.outputThreshold=0.33] — output quantization threshold
   * @returns {Promise<{output: Float32Array|null, trits: Int8Array|null, raw: Object|null}>}
   */
  async infer(modelName, rawFeatures, options = {}) {
    const { ternaryOutput = true, outputThreshold = 0.33 } = options;
    
    if (!this._engine || !this._engine.hasModel(modelName)) {
      return { output: null, trits: null, raw: null };
    }
    
    // Build ternary feature vector
    const { vector } = buildTernaryFeatureVector(rawFeatures);
    
    this._stats.totalInferences++;
    this._stats.ternaryInputs++;
    
    // Run through ONNX via accel.inference
    const raw = await this._engine.infer(modelName, { input: vector });
    
    if (!raw) {
      return { output: null, trits: null, raw: null };
    }
    
    // Extract primary output
    const outputKey = Object.keys(raw)[0];
    const output = raw[outputKey];
    
    // Optionally quantize output to trits
    const trits = ternaryOutput ? quantizeArray(output, outputThreshold) : null;
    
    return { output, trits, raw };
  }

  /**
   * Run ternary consensus across multiple model outputs.
   * 
   * Each model votes with its ternary output, and the final result
   * uses TRIBHUJ majority logic — if no majority, NEUTRAL wins.
   * This is inherently Byzantine-fault tolerant: a single compromised
   * model can't override the consensus.
   * 
   * @param {string[]} modelNames — models to query
   * @param {Float32Array | number[]} rawFeatures — shared input
   * @param {Object} [options] — per-model inference options
   * @returns {Promise<{consensus: Int8Array, votes: Int8Array[], models: string[]}>}
   */
  async consensusInfer(modelNames, rawFeatures, options = {}) {
    const votes = [];
    const activeModels = [];
    
    // Collect votes from all available models
    for (const name of modelNames) {
      const result = await this.infer(name, rawFeatures, { ternaryOutput: true, ...options });
      if (result.trits) {
        votes.push(result.trits);
        activeModels.push(name);
      }
    }
    
    this._stats.consensusVotes++;
    
    if (votes.length === 0) {
      return { consensus: null, votes: [], models: [] };
    }
    
    // Compute element-wise majority using TRIBHUJ
    const outputLen = votes[0].length;
    const consensus = new Int8Array(outputLen);
    
    for (let i = 0; i < outputLen; i++) {
      // Collect votes for this output position
      const posVotes = votes.map(v => v[i] || 0);
      const arr = new TritArray(posVotes);
      consensus[i] = arr.majority().value;
    }
    
    return { consensus, votes, models: activeModels };
  }

  /**
   * Classify a trust score using ternary quantization.
   * Maps KARMA-style trust to the three-state TRIBHUJ representation.
   * 
   * @param {number} trustScore — 0.0 to 1.0
   * @returns {{ trit: number, state: string, confidence: number }}
   */
  classifyTrust(trustScore) {
    // Map trust to balanced range [-1, +1]
    const balanced = (trustScore * 2) - 1;
    
    // Quantize with adaptive threshold
    const trit = quantizeToTrit(balanced, 0.33);
    
    // Confidence is distance from decision boundary
    const confidence = Math.abs(balanced) > 0.33 
      ? Math.min(1, (Math.abs(balanced) - 0.33) / 0.67)
      : 0;
    
    const stateMap = {
      [NEGATIVE]: TritState.DISTRUST,
      [NEUTRAL]:  TritState.UNVERIFIED,
      [POSITIVE]: TritState.TRUST,
    };
    
    return {
      trit,
      state: trit === NEGATIVE ? 'DISTRUST' : trit === POSITIVE ? 'TRUST' : 'UNVERIFIED',
      confidence: +confidence.toFixed(3),
    };
  }

  /**
   * Detect anomalies using ternary family balance.
   * 
   * A healthy feature distribution has roughly equal A/B/C families.
   * Significant skew indicates potential anomaly.
   * 
   * @param {Float32Array | number[]} features 
   * @param {number} [anomalyThreshold=1.5] — balance score above this = anomaly
   * @returns {{ isAnomaly: boolean, balanceScore: number, distribution: Object }}
   */
  detectFamilyAnomaly(features, anomalyThreshold = 1.5) {
    const encoded = sstEncodeFeatures(
      Array.from(features).map(v => Math.round(Math.abs(v * 1000)))
    );
    const balance = familyBalance(encoded.families);
    
    return {
      isAnomaly: balance.balance > anomalyThreshold,
      balanceScore: balance.balance,
      distribution: { a: balance.a, b: balance.b, c: balance.c },
    };
  }

  /**
   * Get adapter statistics.
   * @returns {Object}
   */
  getStats() {
    return { ...this._stats };
  }
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  // Quantization
  quantizeToTrit,
  quantizeArray,
  adaptiveQuantize,
  dequantizeTrits,
  
  // SST Feature Encoding
  sstEncodeFeatures,
  familyBalance,
  buildTernaryFeatureVector,
  
  // Inference Adapter
  TernaryInferenceAdapter,
};
