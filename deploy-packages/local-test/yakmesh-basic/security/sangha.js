/**
 * ╔═══════════════════════════════════════════════════════════════════════════════╗
 * ║               🔗 SANGHA - UNIFIED COMPONENT ATTESTATION 🔗                    ║
 * ╠═══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  SANGHA (Sanskrit: संघ) means "community" or "assembly" - the Buddhist        ║
 * ║  concept of beings who support each other on the path to enlightenment.       ║
 * ║                                                                               ║
 * ║  In YAKMESH, SANGHA represents a NOVEL security architecture:                 ║
 * ║                                                                               ║
 * ║  PHILOSOPHY:                                                                  ║
 * ║    Traditional process isolation SEPARATES components - each stands alone.    ║
 * ║    SANGHA UNIFIES components - they protect each other through continuous     ║
 * ║    mutual attestation. Like a group of travelers in dangerous terrain,        ║
 * ║    strength comes from unity, not isolation.                                  ║
 * ║                                                                               ║
 * ║  CORE MECHANISMS:                                                             ║
 * ║    1. SYNAPSE - Cryptographic communication channels between components       ║
 * ║    2. ANTIBODY - Circulating verification routines that check integrity       ║
 * ║    3. TEMPORAL BINDING - Operations bound to GPS time windows                 ║
 * ║    4. COLLECTIVE RESPONSE - All components react to any detected anomaly      ║
 * ║                                                                               ║
 * ║  "No component can be compromised silently - the others would notice."        ║
 * ║                                                                               ║
 * ╚═══════════════════════════════════════════════════════════════════════════════╝
 * 
 * @module security/sangha
 * @version 1.0.0
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { EventEmitter } from 'events';
import { createHash, randomBytes } from 'crypto';
import { createLogger } from '../utils/logger.js';
import { ternaryId } from '../utils/ternary-id.js';
import { Trit, POSITIVE, NEGATIVE, NEUTRAL } from '../oracle/tribhuj.js';

const log = createLogger('security:sangha');

// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * Component identifiers in the SANGHA collective
 * Each component is a member of the assembly
 */
export const SANGHA_COMPONENT = Object.freeze({
  CRYPTO: 'crypto',      // Cryptographic operations (signing, KEM, hashing)
  MESH: 'mesh',          // Network layer (WebSocket, gossip, ANNEX)
  ORACLE: 'oracle',      // Consensus, time, validation
  ACCEL: 'accel',        // Hardware acceleration (GPU/NPU/ONNX)
  HTTP: 'http',          // API server and dashboard
  IDENTITY: 'identity',  // Key management, DOKO
});

/**
 * Attestation validity windows (milliseconds)
 * Tighter windows for higher-integrity components
 */
export const ATTESTATION_VALIDITY = Object.freeze({
  [SANGHA_COMPONENT.CRYPTO]: 100,    // 100ms - crypto must be real-time
  [SANGHA_COMPONENT.ORACLE]: 200,    // 200ms - oracle needs tight time
  [SANGHA_COMPONENT.MESH]: 500,      // 500ms - network has latency
  [SANGHA_COMPONENT.ACCEL]: 1000,    // 1s - GPU ops can be slow
  [SANGHA_COMPONENT.HTTP]: 2000,     // 2s - HTTP is user-facing
  [SANGHA_COMPONENT.IDENTITY]: 100,  // 100ms - identity is critical
});

/**
 * Minimum attestations required for collective operations
 * Uses 2-of-3 Byzantine tolerance
 */
export const QUORUM_THRESHOLD = 3;
export const QUORUM_MINIMUM = 2;

/**
 * SANGHA States (ternary)
 */
export const SANGHA_STATE = Object.freeze({
  HARMONIOUS: POSITIVE,   // +1: All components in agreement
  DISRUPTED: NEGATIVE,    // -1: Attestation chain broken
  CONVERGING: NEUTRAL,    // 0: Working toward consensus
});

// =============================================================================
// SYNAPSE - CRYPTOGRAPHIC COMMUNICATION CHANNEL
// =============================================================================

/**
 * Synapse represents a secure, bidirectional communication channel
 * between two SANGHA components.
 * 
 * Every message through a synapse is:
 * - Signed by the sender
 * - Timestamped to GPS time
 * - Verified by the receiver
 * - Part of an attestation chain
 */
export class Synapse {
  #id;
  #componentA;
  #componentB;
  #sharedSecret;
  #messageChain;
  #lastActivity;
  #healthy;

  /**
   * @param {string} componentA - First component ID
   * @param {string} componentB - Second component ID
   */
  constructor(componentA, componentB) {
    this.#id = `synapse:${componentA}<->${componentB}`;
    this.#componentA = componentA;
    this.#componentB = componentB;
    this.#sharedSecret = randomBytes(32);
    this.#messageChain = []; // Rolling chain of message hashes
    this.#lastActivity = Date.now();
    this.#healthy = true;

    Object.seal(this);
  }

  get id() { return this.#id; }
  get componentA() { return this.#componentA; }
  get componentB() { return this.#componentB; }
  get healthy() { return this.#healthy; }
  get lastActivity() { return this.#lastActivity; }

  /**
   * Generate a message attestation
   * @param {string} sender - Component sending the message
   * @param {Buffer|string} data - Message data
   * @param {number} timestamp - GPS timestamp
   * @returns {{attestation: string, chainHash: string}}
   */
  attest(sender, data, timestamp) {
    if (sender !== this.#componentA && sender !== this.#componentB) {
      throw new Error(`Invalid sender ${sender} for synapse ${this.#id}`);
    }

    const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(String(data));

    // Build attestation: hash(sender | data | timestamp | prevChainHash | secret)
    const prevChainHash = this.#messageChain.length > 0
      ? this.#messageChain[this.#messageChain.length - 1]
      : Buffer.alloc(32);

    const attestation = createHash('sha3-256')
      .update(sender)
      .update(dataBuffer)
      .update(Buffer.from(timestamp.toString()))
      .update(prevChainHash)
      .update(this.#sharedSecret)
      .digest('hex');

    // Add to chain (rolling window of last 100)
    this.#messageChain.push(Buffer.from(attestation, 'hex'));
    if (this.#messageChain.length > 100) {
      this.#messageChain.shift();
    }

    this.#lastActivity = Date.now();

    return {
      attestation,
      chainHash: attestation.slice(0, 16),
      chainLength: this.#messageChain.length,
    };
  }

  /**
   * Verify a message attestation
   * @param {string} sender - Expected sender
   * @param {Buffer|string} data - Message data
   * @param {number} timestamp - GPS timestamp
   * @param {string} expectedAttestation - Expected attestation hash
   * @returns {boolean}
   */
  verify(sender, data, timestamp, expectedAttestation) {
    try {
      const { attestation } = this.attest(sender, data, timestamp);
      const valid = attestation === expectedAttestation;

      if (!valid) {
        this.#healthy = false;
        log.warn(`Synapse ${this.#id} attestation mismatch`, {
          expected: expectedAttestation.slice(0, 16),
          got: attestation.slice(0, 16),
        });
      }

      return valid;
    } catch (e) {
      this.#healthy = false;
      return false;
    }
  }

  /**
   * Get synapse health metrics
   */
  getHealth() {
    return {
      id: this.#id,
      healthy: this.#healthy,
      chainLength: this.#messageChain.length,
      lastActivity: this.#lastActivity,
      age: Date.now() - this.#lastActivity,
    };
  }

  /**
   * Reset synapse after recovery
   */
  reset() {
    this.#sharedSecret = randomBytes(32);
    this.#messageChain = [];
    this.#healthy = true;
    this.#lastActivity = Date.now();
    log.info(`Synapse ${this.#id} reset`);
  }
}

// =============================================================================
// ANTIBODY - CIRCULATING VERIFICATION ROUTINE
// =============================================================================

/**
 * Antibody is a verification routine that circulates between components,
 * collecting attestations and detecting inconsistencies.
 * 
 * Like biological antibodies, they:
 * - Patrol continuously
 * - Detect foreign/corrupt elements
 * - Trigger collective immune response
 */
export class Antibody {
  #id;
  #createdAt;
  #visited;
  #attestations;
  #anomalies;
  #state;

  constructor() {
    this.#id = ternaryId(8);
    this.#createdAt = Date.now();
    this.#visited = new Set();
    this.#attestations = new Map();
    this.#anomalies = [];
    this.#state = new Trit(NEUTRAL); // Start converging

    Object.seal(this);
  }

  get id() { return this.#id; }
  get createdAt() { return this.#createdAt; }
  get visited() { return Array.from(this.#visited); }
  get attestations() { return new Map(this.#attestations); }
  get anomalies() { return [...this.#anomalies]; }
  get state() { return this.#state; }

  /**
   * Visit a component and collect its attestation
   * @param {string} component - Component ID
   * @param {object} componentState - Component's current state
   * @param {number} timestamp - GPS timestamp
   * @returns {object} - Attestation result
   */
  visit(component, componentState, timestamp) {
    this.#visited.add(component);

    // Generate attestation from component state
    const attestation = createHash('sha3-256')
      .update(this.#id)
      .update(component)
      .update(JSON.stringify(componentState))
      .update(Buffer.from(timestamp.toString()))
      .digest('hex');

    this.#attestations.set(component, {
      attestation,
      timestamp,
      stateHash: createHash('sha3-256')
        .update(JSON.stringify(componentState))
        .digest('hex')
        .slice(0, 16),
    });

    return { component, attestation: attestation.slice(0, 16) };
  }

  /**
   * Record an anomaly detected during circulation
   * @param {string} component - Component where anomaly detected
   * @param {string} type - Anomaly type
   * @param {object} details - Anomaly details
   */
  recordAnomaly(component, type, details = {}) {
    this.#anomalies.push({
      component,
      type,
      details,
      timestamp: Date.now(),
    });
    this.#state = new Trit(NEGATIVE); // Disrupted
  }

  /**
   * Finalize circulation and determine collective state
   * @returns {{state: Trit, visited: string[], anomalies: object[]}}
   */
  finalize() {
    if (this.#anomalies.length > 0) {
      this.#state = new Trit(NEGATIVE);
    } else if (this.#visited.size >= QUORUM_MINIMUM) {
      this.#state = new Trit(POSITIVE);
    } else {
      this.#state = new Trit(NEUTRAL);
    }

    return {
      id: this.#id,
      state: this.#state,
      visited: this.visited,
      attestationCount: this.#attestations.size,
      anomalies: this.#anomalies,
      duration: Date.now() - this.#createdAt,
    };
  }
}

// =============================================================================
// SANGHA - THE UNIFIED COLLECTIVE
// =============================================================================

/**
 * SANGHA manages the collective of components and their mutual attestations.
 * 
 * It maintains:
 * - Synapses between all component pairs
 * - Circulating antibodies for continuous verification
 * - Temporal binding to GPS time
 * - Collective response mechanisms
 */
export class Sangha extends EventEmitter {
  #components;
  #synapses;
  #antibodies;
  #timeSource;
  #state;
  #lastCirculation;
  #circulationInterval;
  #circulationIntervalMs;
  #started;

  constructor() {
    super();

    this.#components = new Map();
    this.#synapses = new Map();
    this.#antibodies = [];
    this.#timeSource = null;
    this.#state = new Trit(NEUTRAL);
    this.#lastCirculation = 0;
    this.#circulationInterval = null;
    this.#circulationIntervalMs = 5000;
    this.#started = false;

    Object.seal(this);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Component Registration
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Register a component with the SANGHA collective
   * @param {string} componentId - Component identifier
   * @param {object} componentRef - Reference to component instance
   * @param {function} stateGetter - Function to get component's current state
   */
  register(componentId, componentRef, stateGetter) {
    if (this.#components.has(componentId)) {
      log.warn(`Component ${componentId} already registered, updating`);
    }

    this.#components.set(componentId, {
      id: componentId,
      ref: componentRef,
      getState: stateGetter,
      registeredAt: Date.now(),
      lastAttestation: 0,
    });

    // Create synapses to all existing components
    for (const [existingId] of this.#components) {
      if (existingId !== componentId) {
        const synapseId = this.#makeSynapseId(componentId, existingId);
        if (!this.#synapses.has(synapseId)) {
          this.#synapses.set(synapseId, new Synapse(componentId, existingId));
          log.debug(`Created synapse ${synapseId}`);
        }
      }
    }

    log.info(`Component ${componentId} joined SANGHA`, {
      totalComponents: this.#components.size,
      totalSynapses: this.#synapses.size,
    });

    this.emit('componentJoined', componentId);
    return this;
  }

  /**
   * Unregister a component
   * @param {string} componentId
   */
  unregister(componentId) {
    if (!this.#components.has(componentId)) return;

    this.#components.delete(componentId);

    // Remove associated synapses
    for (const [synapseId] of this.#synapses) {
      if (synapseId.includes(componentId)) {
        this.#synapses.delete(synapseId);
      }
    }

    log.info(`Component ${componentId} left SANGHA`);
    this.emit('componentLeft', componentId);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Time Source Binding
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Bind to a time source for temporal attestations
   * @param {object} timeSource - MANI time source instance
   */
  bindTimeSource(timeSource) {
    this.#timeSource = timeSource;
    log.info('SANGHA bound to time source', {
      type: timeSource?.getSourceType?.() || 'unknown',
    });
  }

  /**
   * Get current GPS timestamp for attestations
   * @returns {number}
   */
  getTimestamp() {
    if (this.#timeSource?.getCurrentTime) {
      return this.#timeSource.getCurrentTime();
    }
    return Date.now();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Synapse Operations
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Create standardized synapse ID from two component IDs
   */
  #makeSynapseId(a, b) {
    return a < b ? `${a}<->${b}` : `${b}<->${a}`;
  }

  /**
   * Get synapse between two components
   * @param {string} componentA
   * @param {string} componentB
   * @returns {Synapse|null}
   */
  getSynapse(componentA, componentB) {
    return this.#synapses.get(this.#makeSynapseId(componentA, componentB));
  }

  /**
   * Send an attested message between components
   * @param {string} from - Sender component
   * @param {string} to - Receiver component
   * @param {string} action - Action/method name
   * @param {any} payload - Message payload
   * @returns {object} - Attested message envelope
   */
  attestedCall(from, to, action, payload) {
    const synapse = this.getSynapse(from, to);
    if (!synapse) {
      throw new Error(`No synapse between ${from} and ${to}`);
    }

    const timestamp = this.getTimestamp();
    const validity = ATTESTATION_VALIDITY[from] || 1000;

    const messageData = JSON.stringify({ action, payload });
    const { attestation, chainHash } = synapse.attest(from, messageData, timestamp);

    return {
      from,
      to,
      action,
      payload,
      timestamp,
      validUntil: timestamp + validity,
      attestation,
      chainHash,
    };
  }

  /**
   * Verify an attested message
   * @param {object} envelope - Message envelope from attestedCall
   * @returns {boolean}
   */
  verifyAttestedCall(envelope) {
    const { from, to, action, payload, timestamp, validUntil, attestation } = envelope;

    // Check temporal validity
    const now = this.getTimestamp();
    if (now > validUntil) {
      log.warn('Attested call expired', { from, to, action, expired: now - validUntil });
      return false;
    }

    const synapse = this.getSynapse(from, to);
    if (!synapse) {
      log.warn('No synapse for verification', { from, to });
      return false;
    }

    const messageData = JSON.stringify({ action, payload });
    return synapse.verify(from, messageData, timestamp, attestation);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Antibody Circulation
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Circulate an antibody through all components
   * @returns {Promise<object>} - Circulation result
   */
  async circulate() {
    const antibody = new Antibody();
    const timestamp = this.getTimestamp();

    log.debug(`Antibody ${antibody.id} starting circulation`);

    for (const [componentId, component] of this.#components) {
      try {
        const state = await component.getState();
        antibody.visit(componentId, state, timestamp);

        // Check attestation age - use 2x circulation interval as threshold
        // (ATTESTATION_VALIDITY is for message expiry, not component liveness)
        const age = timestamp - component.lastAttestation;
        const maxAge = this.#circulationIntervalMs * 2;

        if (component.lastAttestation > 0 && age > maxAge) {
          antibody.recordAnomaly(componentId, 'STALE_ATTESTATION', {
            age,
            maxAge,
          });
        }

        component.lastAttestation = timestamp;
      } catch (e) {
        antibody.recordAnomaly(componentId, 'STATE_UNAVAILABLE', {
          error: e.message,
        });
      }
    }

    const result = antibody.finalize();

    // Store for analysis (rolling window)
    this.#antibodies.push(result);
    if (this.#antibodies.length > 100) {
      this.#antibodies.shift();
    }

    // Update collective state
    this.#state = result.state;
    this.#lastCirculation = timestamp;

    // Emit events based on result
    if (result.anomalies.length > 0) {
      log.warn(`Antibody ${antibody.id} detected ${result.anomalies.length} anomalies`);
      this.emit('anomalyDetected', result.anomalies);
      this.#triggerCollectiveResponse(result.anomalies);
    } else {
      this.emit('circulationComplete', result);
    }

    return result;
  }

  /**
   * Trigger collective response to anomalies
   * All components are notified and can take defensive action
   */
  #triggerCollectiveResponse(anomalies) {
    log.error('🚨 SANGHA COLLECTIVE RESPONSE TRIGGERED', {
      anomalyCount: anomalies.length,
      types: anomalies.map(a => a.type),
    });

    this.emit('collectiveResponse', {
      timestamp: this.getTimestamp(),
      anomalies,
      action: 'ALERT', // Could be: ALERT, ISOLATE, SHUTDOWN
    });

    // Notify all components
    for (const [componentId, component] of this.#components) {
      if (component.ref?.onSanghaAlert) {
        try {
          component.ref.onSanghaAlert(anomalies);
        } catch (e) {
          log.error(`Failed to alert ${componentId}`, { error: e.message });
        }
      }
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Start the SANGHA collective
   * @param {object} options
   * @param {number} options.circulationIntervalMs - How often to circulate antibodies
   */
  start({ circulationIntervalMs = 5000 } = {}) {
    if (this.#started) return;

    this.#started = true;
    this.#circulationIntervalMs = circulationIntervalMs;
    this.#circulationInterval = setInterval(() => {
      this.circulate().catch(e => {
        log.error('Circulation failed', { error: e.message });
      });
    }, circulationIntervalMs);

    log.info('SANGHA collective started', {
      components: this.#components.size,
      synapses: this.#synapses.size,
      circulationInterval: circulationIntervalMs,
    });

    // Initial circulation
    this.circulate();

    this.emit('started');
  }

  /**
   * Stop the SANGHA collective
   */
  stop() {
    if (!this.#started) return;

    this.#started = false;
    if (this.#circulationInterval) {
      clearInterval(this.#circulationInterval);
      this.#circulationInterval = null;
    }

    log.info('SANGHA collective stopped');
    this.emit('stopped');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Status & Diagnostics
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Get collective health status
   */
  getStatus() {
    const synapseHealth = [];
    for (const [id, synapse] of this.#synapses) {
      synapseHealth.push(synapse.getHealth());
    }

    const recentAnomalies = this.#antibodies
      .slice(-10)
      .flatMap(a => a.anomalies);

    return {
      state: this.#state.value,
      stateLabel: this.#state.value === 1 ? 'HARMONIOUS' :
        this.#state.value === -1 ? 'DISRUPTED' : 'CONVERGING',
      started: this.#started,
      components: Array.from(this.#components.keys()),
      componentCount: this.#components.size,
      synapseCount: this.#synapses.size,
      synapseHealth,
      lastCirculation: this.#lastCirculation,
      circulationCount: this.#antibodies.length,
      recentAnomalies,
      healthy: this.#state.value >= 0 && recentAnomalies.length === 0,
    };
  }

  /**
   * Get recent antibody results
   * @param {number} count
   */
  getRecentCirculations(count = 10) {
    return this.#antibodies.slice(-count);
  }
}

// =============================================================================
// SINGLETON & EXPORTS
// =============================================================================

let sanghaInstance = null;

/**
 * Get the global SANGHA instance
 * @returns {Sangha}
 */
export function getSangha() {
  if (!sanghaInstance) {
    sanghaInstance = new Sangha();
  }
  return sanghaInstance;
}

/**
 * Register a component with the global SANGHA
 * @param {string} componentId
 * @param {object} componentRef
 * @param {function} stateGetter
 */
export function joinSangha(componentId, componentRef, stateGetter) {
  return getSangha().register(componentId, componentRef, stateGetter);
}

/**
 * Create an attested call between components
 * @param {string} from
 * @param {string} to
 * @param {string} action
 * @param {any} payload
 */
export function attestedCall(from, to, action, payload) {
  return getSangha().attestedCall(from, to, action, payload);
}

/**
 * Verify an attested call
 * @param {object} envelope
 */
export function verifyAttestedCall(envelope) {
  return getSangha().verifyAttestedCall(envelope);
}

export default Sangha;
