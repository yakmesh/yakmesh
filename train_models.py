#!/usr/bin/env python3
"""
YAKMESH — ONNX Training Pipeline
==================================
Generates synthetic mesh-network security data and trains 3 neural
network models as ONNX files for NPU/GPU/CPU inference via ACCEL.

Models:
  1. entropy-sentinel  — Seed / key material quality scoring
  2. sakshi-anomaly    — Behavioral velocity anomaly detection
  3. karma-trust       — Multi-source trust level prediction

Architecture follows c2c's pioneering pattern:
  - numpy synthetic data generator per model domain
  - Hand-crafted forward passes + backprop (no PyTorch needed)
  - ONNX export via onnx.helper (opset 18)
  - He initialization, gradient clipping, best-loss checkpointing

All models use hand-crafted forward passes with numpy — no PyTorch needed.

 Copyright 2026 YAKMESH Contributors — MIT License
"""

import numpy as np
import onnx
from onnx import helper, TensorProto, numpy_helper
import os
import json
import time

np.random.seed(144)  # 12th Fibonacci — Hurwitz constellation harmony

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
os.makedirs(OUT_DIR, exist_ok=True)


# =============================================================================
# ONNX MLP BUILDER (ported from c2c)
# =============================================================================

def build_mlp_onnx(name, layer_specs, input_name='input', output_name='output',
                   final_activation='none', description=''):
    """
    Build an ONNX MLP from trained numpy weight matrices.

    layer_specs: list of (W, b) tuples for each layer
    final_activation: 'sigmoid', 'softmax', or 'none'
    """
    nodes = []
    initializers = []
    input_dim = layer_specs[0][0].shape[0]

    # Input
    X = helper.make_tensor_value_info(input_name, TensorProto.FLOAT, [1, input_dim])

    prev_output = input_name
    for i, (W, b) in enumerate(layer_specs):
        w_name = f'W{i}'
        b_name = f'b{i}'
        mm_name = f'mm{i}'
        add_name = f'add{i}'
        is_last = (i == len(layer_specs) - 1)
        act_name = f'relu{i}' if not is_last else 'pre_out'

        # Weight and bias initializers
        initializers.append(numpy_helper.from_array(W.astype(np.float32), w_name))
        initializers.append(numpy_helper.from_array(b.astype(np.float32), b_name))

        # MatMul
        nodes.append(helper.make_node('MatMul', [prev_output, w_name], [mm_name]))
        # Add bias
        nodes.append(helper.make_node('Add', [mm_name, b_name], [add_name]))

        if not is_last:
            # ReLU activation
            nodes.append(helper.make_node('Relu', [add_name], [act_name]))
            prev_output = act_name
        else:
            prev_output = add_name

    # Final activation
    output_dim = layer_specs[-1][0].shape[1]
    out_name = output_name

    if final_activation == 'sigmoid':
        nodes.append(helper.make_node('Sigmoid', [prev_output], [out_name]))
    elif final_activation == 'softmax':
        nodes.append(helper.make_node('Softmax', [prev_output], [out_name], axis=1))
    else:
        out_name = prev_output
        if out_name != output_name:
            nodes.append(helper.make_node('Identity', [out_name], [output_name]))
            out_name = output_name

    Y = helper.make_tensor_value_info(out_name, TensorProto.FLOAT, [1, output_dim])

    graph = helper.make_graph(nodes, name, [X], [Y], initializers)
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid('', 18)])
    model.doc_string = description

    onnx.checker.check_model(model)
    return model


# =============================================================================
# NUMPY FORWARD PASS + TRAINING (ported from c2c)
# =============================================================================

def relu(x):
    return np.maximum(0, x)

def sigmoid(x):
    return 1.0 / (1.0 + np.exp(-np.clip(x, -20, 20)))

def softmax(x, axis=-1):
    e = np.exp(x - np.max(x, axis=axis, keepdims=True))
    return e / e.sum(axis=axis, keepdims=True)

def forward_mlp(x, layers, final='none'):
    """Forward pass through MLP layers."""
    h = x
    for i, (W, b) in enumerate(layers):
        h = h @ W + b
        if i < len(layers) - 1:
            h = relu(h)
    if final == 'sigmoid':
        h = sigmoid(h)
    elif final == 'softmax':
        h = softmax(h)
    return h


def train_mlp(X, Y, hidden_dims, lr=0.01, epochs=500, final='none',
              verbose=True, name='model'):
    """
    Train MLP with backprop.
    X: (N, input_dim)
    Y: (N, output_dim)
    hidden_dims: list of hidden layer sizes
    """
    N, in_dim = X.shape
    out_dim = Y.shape[1]

    # Build layer dimensions
    dims = [in_dim] + hidden_dims + [out_dim]
    layers = []
    for i in range(len(dims) - 1):
        # He initialization
        scale = np.sqrt(2.0 / dims[i])
        W = np.random.randn(dims[i], dims[i + 1]).astype(np.float64) * scale
        b = np.zeros((1, dims[i + 1]), dtype=np.float64)
        layers.append([W, b])

    best_loss = float('inf')
    best_layers = None

    for epoch in range(epochs):
        # Forward pass
        activations = [X]
        pre_activations = []
        h = X
        for i, (W, b) in enumerate(layers):
            z = h @ W + b
            pre_activations.append(z)
            if i < len(layers) - 1:
                h = relu(z)
            else:
                if final == 'sigmoid':
                    h = sigmoid(z)
                elif final == 'softmax':
                    h = softmax(z)
                else:
                    h = z
            activations.append(h)

        output = activations[-1]

        # Loss
        if final == 'softmax':
            loss = -np.mean(np.sum(Y * np.log(output + 1e-8), axis=1))
        else:
            loss = np.mean((output - Y) ** 2)

        if loss < best_loss:
            best_loss = loss
            best_layers = [(W.copy(), b.copy()) for W, b in layers]

        # Backward pass
        if final == 'sigmoid':
            dh = (output - Y) * output * (1 - output) * (2.0 / N)
        elif final == 'softmax':
            dh = (output - Y) / N
        else:
            dh = 2.0 * (output - Y) / N

        for i in range(len(layers) - 1, -1, -1):
            W, b = layers[i]
            a_prev = activations[i]

            dW = a_prev.T @ dh
            db = dh.sum(axis=0, keepdims=True)

            if i > 0:
                dh = dh @ W.T
                # ReLU derivative
                dh = dh * (pre_activations[i - 1] > 0).astype(np.float64)

            # Gradient clipping
            dW = np.clip(dW, -5, 5)
            db = np.clip(db, -5, 5)

            layers[i][0] -= lr * dW
            layers[i][1] -= lr * db

        if verbose and (epoch % 100 == 0 or epoch == epochs - 1):
            print(f'  {name}: epoch {epoch:4d} loss={loss:.6f}')

    print(f'  {name}: best_loss={best_loss:.6f}')
    return [(W.astype(np.float32), b.astype(np.float32)) for W, b in best_layers]


# =============================================================================
# MODEL 1: ENTROPY SENTINEL
# =============================================================================
# Input:  32 features (one per byte of a 256-bit seed, normalized to [0,1])
# Output: 1 float — quality_score ∈ [0, 1]
#
# The model learns to detect pathological byte patterns:
#   - All zeros → 0.0 (terrible)
#   - All same byte → ~0.05
#   - Sequential bytes → ~0.15
#   - Low diversity → ~0.3
#   - Biased distribution → ~0.5
#   - High-quality random → ~0.95
#
# Architecture: 32 → [48, 32, 16] → 1 (sigmoid)
# =============================================================================

def gen_entropy_data(n_samples=8000):
    """Generate synthetic entropy quality training data."""
    X_list = []
    Y_list = []
    noise = np.random.uniform

    for _ in range(n_samples):
        quality_class = np.random.choice([
            'excellent', 'good', 'mediocre', 'poor', 'terrible'
        ], p=[0.30, 0.25, 0.20, 0.15, 0.10])

        if quality_class == 'excellent':
            # High-quality random bytes (CSPRNG-like)
            data = np.random.randint(0, 256, size=32).astype(np.float64)
            score = np.clip(0.88 + noise(0, 0.10), 0.80, 1.0)

        elif quality_class == 'good':
            # Decent randomness with slight bias
            data = np.random.randint(0, 256, size=32).astype(np.float64)
            # Introduce slight bias toward low or high bytes
            bias_direction = np.random.choice(['low', 'high'])
            n_biased = np.random.randint(3, 8)
            if bias_direction == 'low':
                data[:n_biased] = np.random.randint(0, 32, size=n_biased)
            else:
                data[:n_biased] = np.random.randint(224, 256, size=n_biased)
            np.random.shuffle(data)
            score = np.clip(0.65 + noise(0, 0.12), 0.50, 0.85)

        elif quality_class == 'mediocre':
            # Moderate patterns — repeated subsequences, limited range
            pattern_type = np.random.choice(['limited_range', 'repeated', 'structured'])
            if pattern_type == 'limited_range':
                # Only uses partial byte range
                range_low = np.random.randint(0, 128)
                range_high = range_low + np.random.randint(32, 96)
                data = np.random.randint(range_low, min(256, range_high), size=32).astype(np.float64)
            elif pattern_type == 'repeated':
                # Short pattern repeated
                pat_len = np.random.randint(2, 8)
                pattern = np.random.randint(0, 256, size=pat_len)
                data = np.tile(pattern, 32 // pat_len + 1)[:32].astype(np.float64)
                # Add some noise
                mask = np.random.random(32) < 0.3
                data[mask] = np.random.randint(0, 256, size=mask.sum())
            else:
                # Arithmetic progression with noise
                start = np.random.randint(0, 200)
                step = np.random.randint(1, 8)
                data = np.array([(start + i * step) % 256 for i in range(32)], dtype=np.float64)
                data += np.random.randint(-10, 11, size=32)
                data = np.clip(data, 0, 255)
            score = np.clip(0.35 + noise(0, 0.10), 0.20, 0.55)

        elif quality_class == 'poor':
            # Significant bias — many zeros, many same byte, near-constant
            bias_type = np.random.choice(['many_zeros', 'dominant_byte', 'low_diversity'])
            if bias_type == 'many_zeros':
                n_zeros = np.random.randint(16, 28)
                data = np.zeros(32)
                nonzero_indices = np.random.choice(32, 32 - n_zeros, replace=False)
                data[nonzero_indices] = np.random.randint(1, 256, size=32 - n_zeros)
            elif bias_type == 'dominant_byte':
                dominant = np.random.randint(0, 256)
                data = np.full(32, dominant, dtype=np.float64)
                n_different = np.random.randint(2, 8)
                indices = np.random.choice(32, n_different, replace=False)
                data[indices] = np.random.randint(0, 256, size=n_different)
            else:
                # Only 3-5 unique values
                n_unique = np.random.randint(3, 6)
                palette = np.random.randint(0, 256, size=n_unique)
                data = np.random.choice(palette, size=32).astype(np.float64)
            score = np.clip(0.12 + noise(0, 0.08), 0.02, 0.25)

        else:  # terrible
            # Degenerate: all zeros, all ones, or constant
            degen_type = np.random.choice(['all_zeros', 'all_ff', 'constant', 'counter'])
            if degen_type == 'all_zeros':
                data = np.zeros(32)
            elif degen_type == 'all_ff':
                data = np.full(32, 255.0)
            elif degen_type == 'constant':
                data = np.full(32, float(np.random.randint(0, 256)))
            else:
                data = np.arange(32, dtype=np.float64) * (256 / 32)
            score = np.clip(0.02 + noise(0, 0.03), 0.0, 0.10)

        # Normalize bytes to [0, 1]
        x = data / 255.0
        y = np.array([score])

        X_list.append(x)
        Y_list.append(y)

    return np.array(X_list), np.array(Y_list)


# =============================================================================
# MODEL 2: SAKSHI ANOMALY DETECTOR
# =============================================================================
# Input: 12 features — behavioral velocity snapshot:
#   0: message_rate         (messages/min, normalized)
#   1: gossip_ratio         (fraction gossip vs direct)
#   2: error_rate           (invalid msgs/sigs, normalized)
#   3: attestation_rate     (revocation attestations, normalized)
#   4: connection_churn     (connect/disconnect freq, normalized)
#   5: response_latency     (avg response time, normalized)
#   6: uptime_percent       (0-1)
#   7: network_age_days     (normalized, capped at 365)
#   8: karma_score          (normalized 0-1)
#   9: has_aesni            (0 or 1 — hardware attestation)
#  10: time_source_quality  (0=system, 0.5=ntp, 1.0=ptp)
#  11: observation_count    (normalized, capped at 1000)
#
# Output: 4 floats (sigmoid):
#   0: anomaly_score    — overall anomaly probability [0,1]
#   1: is_sybil         — Sybil attack probability
#   2: is_eclipse       — Eclipse attack probability
#   3: is_flood         — Flood/DoS probability
#
# Architecture: 12 → [24, 16] → 4 (sigmoid)
# =============================================================================

BEHAVIOR_PROFILES = {
    'honest_stable': {
        'message_rate': (0.3, 0.1),     # moderate, consistent
        'gossip_ratio': (0.5, 0.15),     # balanced
        'error_rate': (0.02, 0.02),      # very low
        'attestation_rate': (0.05, 0.03),
        'connection_churn': (0.1, 0.05), # stable connections
        'response_latency': (0.3, 0.1),  # reasonable
        'uptime': (0.9, 0.08),
        'age_days': (180, 100),
        'karma': (0.7, 0.15),
        'aesni': 0.8,                    # usually has HW
        'time_quality': (0.8, 0.15),
        'obs_count': (500, 200),
    },
    'honest_new': {
        'message_rate': (0.2, 0.1),
        'gossip_ratio': (0.4, 0.2),
        'error_rate': (0.05, 0.03),      # slightly more errors (learning)
        'attestation_rate': (0.02, 0.02),
        'connection_churn': (0.2, 0.1),  # establishing connections
        'response_latency': (0.4, 0.15),
        'uptime': (0.6, 0.2),
        'age_days': (15, 10),
        'karma': (0.3, 0.15),
        'aesni': 0.5,
        'time_quality': (0.5, 0.2),
        'obs_count': (30, 20),
    },
    'sybil_attacker': {
        'message_rate': (0.7, 0.15),     # higher than normal
        'gossip_ratio': (0.8, 0.1),      # heavy gossip to spread influence
        'error_rate': (0.1, 0.05),       # occasional errors
        'attestation_rate': (0.02, 0.02),
        'connection_churn': (0.6, 0.15), # connects to many peers rapidly
        'response_latency': (0.15, 0.08),# fast (automated)
        'uptime': (0.95, 0.03),          # always on
        'age_days': (5, 3),              # very new
        'karma': (0.1, 0.05),            # minimal karma
        'aesni': 0.3,                    # often VMs
        'time_quality': (0.3, 0.15),     # cheap time source
        'obs_count': (10, 5),
    },
    'eclipse_attacker': {
        'message_rate': (0.5, 0.15),
        'gossip_ratio': (0.2, 0.1),      # mostly direct (targeting victims)
        'error_rate': (0.08, 0.04),
        'attestation_rate': (0.3, 0.15), # files lots of attestations
        'connection_churn': (0.4, 0.1),  # moderate churn
        'response_latency': (0.2, 0.1),
        'uptime': (0.92, 0.05),
        'age_days': (30, 20),
        'karma': (0.25, 0.1),
        'aesni': 0.5,
        'time_quality': (0.4, 0.2),
        'obs_count': (80, 40),
    },
    'flood_attacker': {
        'message_rate': (0.95, 0.04),    # extremely high
        'gossip_ratio': (0.9, 0.05),     # mostly gossip
        'error_rate': (0.3, 0.15),       # many malformed messages
        'attestation_rate': (0.01, 0.01),
        'connection_churn': (0.3, 0.15),
        'response_latency': (0.05, 0.03),# very fast (automated)
        'uptime': (0.85, 0.1),
        'age_days': (3, 2),
        'karma': (0.05, 0.03),
        'aesni': 0.2,
        'time_quality': (0.2, 0.1),
        'obs_count': (5, 3),
    },
    'honest_relay': {
        'message_rate': (0.6, 0.15),     # higher — relaying for network
        'gossip_ratio': (0.6, 0.1),      # balanced-high gossip (relaying)
        'error_rate': (0.01, 0.01),      # very low
        'attestation_rate': (0.08, 0.04),
        'connection_churn': (0.15, 0.08),
        'response_latency': (0.2, 0.08), # fast
        'uptime': (0.95, 0.03),
        'age_days': (300, 60),
        'karma': (0.85, 0.1),
        'aesni': 0.9,
        'time_quality': (0.9, 0.08),
        'obs_count': (800, 150),
    },
}


def gen_sakshi_sample(profile_name, profile):
    """Generate one behavioral velocity sample from a profile."""
    noise = np.random.normal

    def sample_feature(key):
        if isinstance(profile[key], tuple):
            mean, std = profile[key]
            return np.clip(mean + noise(0, std), 0, 1)
        return profile[key]

    x = np.array([
        sample_feature('message_rate'),
        sample_feature('gossip_ratio'),
        sample_feature('error_rate'),
        sample_feature('attestation_rate'),
        sample_feature('connection_churn'),
        sample_feature('response_latency'),
        sample_feature('uptime'),
        min(1.0, sample_feature('age_days') / 365.0),  # normalize age
        sample_feature('karma'),
        1.0 if np.random.random() < profile['aesni'] else 0.0,
        sample_feature('time_quality'),
        min(1.0, sample_feature('obs_count') / 1000.0),  # normalize count
    ])

    # Labels
    if profile_name in ('sybil_attacker',):
        y = np.array([0.9, 0.9, 0.1, 0.1])   # high anomaly, high sybil
    elif profile_name in ('eclipse_attacker',):
        y = np.array([0.85, 0.1, 0.9, 0.05])  # high anomaly, high eclipse
    elif profile_name in ('flood_attacker',):
        y = np.array([0.95, 0.05, 0.05, 0.95]) # high anomaly, high flood
    elif profile_name in ('honest_new',):
        y = np.array([0.15, 0.05, 0.02, 0.03]) # slightly elevated (new = uncertain)
    elif profile_name in ('honest_relay',):
        y = np.array([0.02, 0.01, 0.01, 0.02]) # very low (established relay)
    else:  # honest_stable
        y = np.array([0.05, 0.02, 0.01, 0.02]) # very low

    # Add noise to labels
    y = np.clip(y + noise(0, 0.03, size=4), 0, 1)
    return x, y


def gen_sakshi_data(n_per_profile=1200):
    """Generate synthetic SAKSHI anomaly detection training data."""
    X_list = []
    Y_list = []

    for name, profile in BEHAVIOR_PROFILES.items():
        for _ in range(n_per_profile):
            x, y = gen_sakshi_sample(name, profile)
            X_list.append(x)
            Y_list.append(y)

    # Shuffle
    X = np.array(X_list)
    Y = np.array(Y_list)
    perm = np.random.permutation(len(X))
    return X[perm], Y[perm]


# =============================================================================
# MODEL 3: KARMA TRUST PREDICTOR
# =============================================================================
# Input: 14 features — multi-source trust evidence:
#   0: doko_verified        (trit: -1=NEGATIVE, 0=NEUTRAL, 1=POSITIVE → norm)
#   1: doko_hash_present    (0 or 1)
#   2: mesh_quorum_verified (trit normalized)
#   3: quorum_size          (normalized, max 10)
#   4: quorum_diversity     (0 or 1)
#   5: ssl_verified         (trit normalized)
#   6: ssl_type             (0=none, 0.33=self-signed, 0.67=doko-bound, 1=ca-signed)
#   7: domain_verified      (trit normalized)
#   8: age_days             (normalized, capped at 365)
#   9: uptime_percent       (0-1)
#  10: karma_score_current  (0-1)
#  11: beacon_consistency   (0-1)
#  12: strike_count         (0, 1, 2, 3 normalized to 0-1)
#  13: days_since_update    (normalized, capped at 90)
#
# Output: 4 floats (softmax) — probability of each KarmaLevel:
#   0: UNTRUSTED    (level 0)
#   1: SEEKING      (level 1)
#   2: AWAKENED     (level 2)
#   3: ENLIGHTENED  (level 3)
#
# Architecture: 14 → [24, 16] → 4 (softmax)
# =============================================================================

KARMA_PROFILES = {
    'untrusted_failed_doko': {
        'doko': -1, 'doko_hash': 0,
        'mesh': 0, 'quorum': 0, 'diversity': 0,
        'ssl': 0, 'ssl_type': 0,
        'domain': 0,
        'age': (5, 3), 'uptime': (0.3, 0.2),
        'karma': (0.05, 0.03), 'beacon': (0.1, 0.1),
        'strikes': (2, 1), 'stale': (30, 20),
        'label': [1, 0, 0, 0],
    },
    'untrusted_decayed': {
        'doko': 1, 'doko_hash': 1,
        'mesh': 0, 'quorum': 0, 'diversity': 0,
        'ssl': 0, 'ssl_type': 0,
        'domain': 0,
        'age': (200, 50), 'uptime': (0.1, 0.05),
        'karma': (0.02, 0.02), 'beacon': (0.0, 0.02),
        'strikes': (1, 1), 'stale': (80, 10),
        'label': [1, 0, 0, 0],
    },
    'untrusted_strike3': {
        'doko': 1, 'doko_hash': 1,
        'mesh': 1, 'quorum': (4, 2), 'diversity': 1,
        'ssl': 1, 'ssl_type': 1.0,
        'domain': 1,
        'age': (100, 30), 'uptime': (0.5, 0.2),
        'karma': (0.2, 0.1), 'beacon': (0.3, 0.1),
        'strikes': (3, 0), 'stale': (1, 1),
        'label': [1, 0, 0, 0],
    },
    'seeking_new': {
        'doko': 1, 'doko_hash': 1,
        'mesh': 0, 'quorum': 0, 'diversity': 0,
        'ssl': 0, 'ssl_type': 0,
        'domain': 0,
        'age': (10, 5), 'uptime': (0.5, 0.2),
        'karma': (0.15, 0.1), 'beacon': (0.2, 0.1),
        'strikes': (0, 0), 'stale': (2, 2),
        'label': [0, 1, 0, 0],
    },
    'seeking_partial': {
        'doko': 1, 'doko_hash': 1,
        'mesh': 0, 'quorum': (1, 1), 'diversity': 0,
        'ssl': 1, 'ssl_type': 0.33,
        'domain': 0,
        'age': (30, 15), 'uptime': (0.6, 0.15),
        'karma': (0.3, 0.1), 'beacon': (0.5, 0.15),
        'strikes': (0, 0), 'stale': (3, 3),
        'label': [0, 1, 0, 0],
    },
    'awakened_mesh': {
        'doko': 1, 'doko_hash': 1,
        'mesh': 1, 'quorum': (5, 2), 'diversity': 1,
        'ssl': 0, 'ssl_type': 0.33,
        'domain': 0,
        'age': (60, 20), 'uptime': (0.75, 0.1),
        'karma': (0.55, 0.15), 'beacon': (0.7, 0.1),
        'strikes': (0, 0), 'stale': (1, 1),
        'label': [0, 0, 1, 0],
    },
    'awakened_strong': {
        'doko': 1, 'doko_hash': 1,
        'mesh': 1, 'quorum': (7, 2), 'diversity': 1,
        'ssl': 1, 'ssl_type': 0.67,
        'domain': 0,
        'age': (90, 30), 'uptime': (0.85, 0.08),
        'karma': (0.65, 0.1), 'beacon': (0.8, 0.1),
        'strikes': (0, 0), 'stale': (1, 1),
        'label': [0, 0, 1, 0],
    },
    'enlightened_full': {
        'doko': 1, 'doko_hash': 1,
        'mesh': 1, 'quorum': (8, 2), 'diversity': 1,
        'ssl': 1, 'ssl_type': 1.0,
        'domain': 1,
        'age': (180, 60), 'uptime': (0.92, 0.05),
        'karma': (0.85, 0.08), 'beacon': (0.95, 0.04),
        'strikes': (0, 0), 'stale': (0, 1),
        'label': [0, 0, 0, 1],
    },
    'enlightened_veteran': {
        'doko': 1, 'doko_hash': 1,
        'mesh': 1, 'quorum': (9, 1), 'diversity': 1,
        'ssl': 1, 'ssl_type': 1.0,
        'domain': 1,
        'age': (365, 50), 'uptime': (0.97, 0.02),
        'karma': (0.95, 0.03), 'beacon': (0.98, 0.02),
        'strikes': (0, 0), 'stale': (0, 0),
        'label': [0, 0, 0, 1],
    },
}


def gen_karma_sample(profile):
    """Generate one karma trust evidence sample."""
    noise = np.random.normal

    def val(key):
        v = profile[key]
        if isinstance(v, tuple):
            return np.clip(v[0] + noise(0, v[1]), 0, 1e6)
        return v

    # Normalize trit values from {-1, 0, 1} to {0, 0.5, 1}
    def trit_norm(t):
        return (t + 1) / 2.0

    x = np.array([
        trit_norm(profile['doko']),
        float(profile['doko_hash']),
        trit_norm(profile['mesh']),
        min(1.0, val('quorum') / 10.0),
        float(profile['diversity']),
        trit_norm(profile['ssl']),
        profile['ssl_type'],
        trit_norm(profile['domain']),
        min(1.0, val('age') / 365.0),
        np.clip(val('uptime'), 0, 1),
        np.clip(val('karma'), 0, 1),
        np.clip(val('beacon'), 0, 1),
        min(1.0, val('strikes') / 3.0),
        min(1.0, val('stale') / 90.0),
    ])

    y = np.array(profile['label'], dtype=np.float64)
    # Add label noise
    y = np.clip(y + noise(0, 0.03, size=4), 0, 1)
    y /= y.sum()  # Re-normalize to sum to 1

    return x, y


def gen_karma_data(n_per_profile=1000):
    """Generate synthetic KARMA trust training data."""
    X_list = []
    Y_list = []

    for name, profile in KARMA_PROFILES.items():
        for _ in range(n_per_profile):
            x, y = gen_karma_sample(profile)
            X_list.append(x)
            Y_list.append(y)

    X = np.array(X_list)
    Y = np.array(Y_list)
    perm = np.random.permutation(len(X))
    return X[perm], Y[perm]


# =============================================================================
# MAIN TRAINING PIPELINE
# =============================================================================

def main():
    t_start = time.time()
    results = {}

    print('=' * 60)
    print('YAKMESH ONNX Training Pipeline')
    print('=' * 60)
    print(f'Output: {OUT_DIR}')
    print(f'Random seed: 144 (12th Fibonacci — Hurwitz harmony)')
    print()

    # ─────────────────────────────────────────────────────────────
    # 1. ENTROPY SENTINEL: 32 → [48, 32, 16] → 1 (sigmoid)
    # ─────────────────────────────────────────────────────────────
    print('[1/3] Training entropy-sentinel...')
    X, Y = gen_entropy_data(n_samples=8000)
    layers = train_mlp(X, Y, [48, 32, 16], lr=0.003, epochs=1000,
                       final='sigmoid', name='entropy-sentinel')
    model = build_mlp_onnx('entropy-sentinel', layers,
                           input_name='seed_bytes', output_name='quality_score',
                           final_activation='sigmoid',
                           description='STEADYWATCH entropy quality scorer — '
                                       'detects weak randomness patterns in seed/key material')
    path = os.path.join(OUT_DIR, 'entropy-sentinel.onnx')
    onnx.save(model, path)
    results['entropy-sentinel'] = {
        'inputs': 32, 'hidden': [48, 32, 16], 'outputs': 1,
        'activation': 'sigmoid', 'samples': len(X),
        'size': os.path.getsize(path),
    }
    print(f'  -> Saved {path} ({os.path.getsize(path):,} bytes)')
    print()

    # ─────────────────────────────────────────────────────────────
    # 2. SAKSHI ANOMALY: 12 → [24, 16] → 4 (sigmoid)
    # ─────────────────────────────────────────────────────────────
    print('[2/3] Training sakshi-anomaly...')
    X, Y = gen_sakshi_data(n_per_profile=1200)
    layers = train_mlp(X, Y, [24, 16], lr=0.005, epochs=800,
                       final='sigmoid', name='sakshi-anomaly')
    model = build_mlp_onnx('sakshi-anomaly', layers,
                           input_name='behavior_features', output_name='anomaly_scores',
                           final_activation='sigmoid',
                           description='SAKSHI behavioral velocity anomaly detector — '
                                       'Sybil / Eclipse / Flood attack classification')
    path = os.path.join(OUT_DIR, 'sakshi-anomaly.onnx')
    onnx.save(model, path)
    results['sakshi-anomaly'] = {
        'inputs': 12, 'hidden': [24, 16], 'outputs': 4,
        'activation': 'sigmoid', 'samples': len(X),
        'size': os.path.getsize(path),
    }
    print(f'  -> Saved {path} ({os.path.getsize(path):,} bytes)')
    print()

    # ─────────────────────────────────────────────────────────────
    # 3. KARMA TRUST: 14 → [24, 16] → 4 (softmax)
    # ─────────────────────────────────────────────────────────────
    print('[3/3] Training karma-trust...')
    X, Y = gen_karma_data(n_per_profile=1000)
    layers = train_mlp(X, Y, [24, 16], lr=0.005, epochs=800,
                       final='softmax', name='karma-trust')
    model = build_mlp_onnx('karma-trust', layers,
                           input_name='trust_evidence', output_name='karma_level',
                           final_activation='softmax',
                           description='KARMA trust level predictor — '
                                       'UNTRUSTED / SEEKING / AWAKENED / ENLIGHTENED')
    path = os.path.join(OUT_DIR, 'karma-trust.onnx')
    onnx.save(model, path)
    results['karma-trust'] = {
        'inputs': 14, 'hidden': [24, 16], 'outputs': 4,
        'activation': 'softmax', 'samples': len(X),
        'size': os.path.getsize(path),
    }
    print(f'  -> Saved {path} ({os.path.getsize(path):,} bytes)')
    print()

    # ─────────────────────────────────────────────────────────────
    # SUMMARY
    # ─────────────────────────────────────────────────────────────
    elapsed = time.time() - t_start

    print('=' * 60)
    print(f'TRAINING COMPLETE — {elapsed:.1f}s')
    print('=' * 60)
    total_size = 0
    total_samples = 0
    for name, info in results.items():
        total_size += info['size']
        total_samples += info['samples']
        print(f'  {name:20s}  in={info["inputs"]:2d}  '
              f'hidden={info["hidden"]}  '
              f'out={info["outputs"]}  '
              f'act={info["activation"]:7s}  '
              f'size={info["size"]:>6,} bytes  '
              f'samples={info["samples"]:,}')
    print(f'  {"TOTAL":20s}  '
          f'size={total_size:,} bytes  '
          f'samples={total_samples:,}')
    print(f'  Output directory: {OUT_DIR}')

    # Save manifest
    manifest_path = os.path.join(OUT_DIR, 'manifest.json')
    manifest = {
        'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
        'random_seed': 144,
        'models': results,
        'total_size': total_size,
        'total_samples': total_samples,
        'training_time_seconds': round(elapsed, 1),
    }
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    print(f'  Manifest: {manifest_path}')


if __name__ == '__main__':
    main()
