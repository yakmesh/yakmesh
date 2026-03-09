/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * YakAI Adapter — Embeds yakai into the yakmesh mesh
 *
 * Bridges yakai with the yakmesh node, exposing:
 *   - ComputeScheduler (GPU/NPU/CPU work routing)
 *   - NodeIdentity (persistentId, publicKey)
 *   - Mesh network (peer discovery, gossip)
 *   - ONNX inference engine (via accel.js)
 *
 * Unlike most adapters that sync external data, this adapter provides
 * yakmesh services TO yakai (one-way capability injection).
 *
 * Usage in yakmesh-node server/index.js:
 *   import { YakaiAdapter } from '../adapters/adapter-yakai/index.js';
 *   const yakaiAdapter = new YakaiAdapter(node);
 *   await yakaiAdapter.init();
 *
 * Usage in yakai server/index.js:
 *   import { getYakmeshBridge } from './services/yakmesh-bridge.js';
 *   const bridge = await getYakmeshBridge();
 *   const result = await bridge.scheduleWork({ ... });
 *
 * @module adapters/adapter-yakai
 * @version 1.0.0
 */

import { BaseAdapter } from '../base-adapter.js';

// Message types for gossip
const YAKAI_TOPICS = {
    INFERENCE_REQUEST: 'yakai:inference:request',
    INFERENCE_RESULT: 'yakai:inference:result',
    COMMAND_BROADCAST: 'yakai:command:broadcast',
    MODEL_STATUS: 'yakai:model:status',
};

/**
 * Priority constants matching ComputeScheduler
 */
const Priority = {
    CRITICAL: 0,
    HIGH: 1,
    NORMAL: 2,
    LOW: 3,
};

/**
 * Device affinity matching ComputeScheduler
 */
const Device = {
    GPU: 'gpu',
    NPU: 'npu',
    CPU: 'cpu',
};

export class YakaiAdapter extends BaseAdapter {
    /**
     * @param {import('../../server/index.js').YakmeshNode} node — live yakmesh node instance
     * @param {Object} [config]
     * @param {number} [config.yakaiPort=3092] — yakai server port (for health checks)
     * @param {number} [config.maxConcurrentInference=4] — max simultaneous inference jobs
     */
    constructor(node, config = {}) {
        super(node, config);

        this.yakaiPort = config.yakaiPort || 3092;
        this.maxConcurrentInference = config.maxConcurrentInference || 4;

        // Track active inference sessions from yakai
        this._activeSessions = new Map();

        // Cached references (set during init)
        this._scheduler = null;
        this._identity = null;
        this._inference = null;

        // Stats specific to yakai
        this.stats = {
            ...this.stats,
            inferenceRequests: 0,
            inferenceCompleted: 0,
            inferenceFailed: 0,
            commandsBroadcast: 0,
        };
    }

    /**
     * Initialize the adapter — wire into node's ComputeScheduler + identity
     */
    async init() {
        // Import accel dynamically to get the live scheduler instance
        const accel = await import('../../utils/accel.js');

        this._scheduler = accel.scheduler;
        this._identity = this.node.identity;
        this._inference = accel.inference;

        // Ensure scheduler is initialized
        if (this._scheduler && !this._scheduler._initialized) {
            await this._scheduler.initialize();
        }

        // Listen for inference results from mesh peers (SEVA pattern)
        if (this.node.gossip) {
            this.node.gossip.on('rumor', (topic, data, origin) => {
                this.handleRumor(topic, data, origin);
            });
        }

        this.isInitialized = true;
        this.emit('ready', this.getCapabilities());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Capabilities — what yakai can use from the mesh
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Returns the available capabilities for yakai
     */
    getCapabilities() {
        const hw = this._getHardwareInfo();
        return {
            nodeId: this._identity?.identity?.nodeId || null,
            persistentId: this._identity?.identity?.persistentId || null,
            publicKey: this._identity?.identity?.publicKey
                ? Buffer.from(this._identity.identity.publicKey).toString('base64').slice(0, 32) + '...'
                : null,
            scheduler: {
                available: !!this._scheduler?._initialized,
                devices: Object.keys(this._scheduler?._queues || {}),
                totalTops: hw.totalTops,
            },
            inference: {
                available: !!this._inference,
                provider: this._inference?.provider || 'none',
            },
            mesh: {
                connected: this.node.mesh?.peers?.size > 0,
                peerCount: this.node.mesh?.peers?.size || 0,
            },
        };
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ComputeScheduler bridge — route yakai work through the scheduler
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Schedule a compute task through the yakmesh ComputeScheduler
     *
     * @param {Object} task
     * @param {string} task.type       — task type identifier (e.g. 'sherpa-inference', 'lama-inference', 'whisper-stt')
     * @param {Function} task.work     — async function that performs the compute work
     * @param {string} [task.device]   — preferred device: 'gpu', 'npu', 'cpu' (default: auto)
     * @param {number} [task.priority] — 0=CRITICAL, 1=HIGH, 2=NORMAL, 3=LOW (default: NORMAL)
     * @param {number} [task.timeoutMs] — max execution time in ms (default: 30000)
     * @returns {Promise<*>} — task result
     */
    async scheduleWork(task) {
        if (!this._scheduler?._initialized) {
            // Fallback: run on CPU thread directly if scheduler not available
            return task.work();
        }

        this.stats.inferenceRequests++;

        try {
            const result = await this._scheduler.submit({
                type: task.type || 'yakai-generic',
                work: task.work,
                device: task.device || Device.NPU,  // NPU-first
                priority: task.priority ?? Priority.NORMAL,
                timeout: task.timeoutMs || 30_000,
            });

            this.stats.inferenceCompleted++;
            return result;
        } catch (err) {
            this.stats.inferenceFailed++;
            throw err;
        }
    }

    /**
     * Schedule SHERPA tactician inference (HIGH priority, NPU preferred)
     */
    async scheduleSherpa(work) {
        return this.scheduleWork({
            type: 'sherpa-inference',
            work,
            device: Device.NPU,
            priority: Priority.HIGH,
            timeoutMs: 15_000,
        });
    }

    /**
     * Schedule LAMA strategist inference (NORMAL priority, GPU preferred for larger model)
     */
    async scheduleLama(work) {
        return this.scheduleWork({
            type: 'lama-inference',
            work,
            device: Device.GPU,
            priority: Priority.NORMAL,
            timeoutMs: 60_000,  // LAMA thinking mode takes longer
        });
    }

    /**
     * Schedule Whisper STT inference (HIGH priority, NPU preferred)
     */
    async scheduleWhisper(work) {
        return this.scheduleWork({
            type: 'whisper-stt',
            work,
            device: Device.NPU,
            priority: Priority.HIGH,
            timeoutMs: 10_000,
        });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Identity bridge — expose yakmesh identity to yakai for C2C auth
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Get the yakmesh identity for use in C2C authentication
     */
    getIdentity() {
        if (!this._identity?.identity) return null;

        const id = this._identity.identity;
        return {
            nodeId: id.nodeId,
            persistentId: id.persistentId,
            publicKey: id.publicKey ? Buffer.from(id.publicKey).toString('base64') : null,
            networkId: this.node.oracle?.networkId || null,
            networkName: this.node.oracle?.networkName || null,
        };
    }

    /**
     * Sign a challenge using the node's ML-DSA-65 key
     * Used for yakmesh-based authentication with C2C
     *
     * @param {Uint8Array|string} challenge — challenge bytes or hex string
     * @returns {Promise<{signature: string, publicKey: string}>}
     */
    async signChallenge(challenge) {
        if (!this._identity) throw new Error('Identity not initialized');

        const challengeBytes = typeof challenge === 'string'
            ? Buffer.from(challenge, 'hex')
            : challenge;

        const signature = await this._identity.sign(challengeBytes);

        return {
            signature: Buffer.from(signature).toString('base64'),
            publicKey: Buffer.from(this._identity.identity.publicKey).toString('base64'),
            persistentId: this._identity.identity.persistentId,
        };
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Inference engine bridge — direct ONNX access for yakai
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Run inference on an ONNX model through the mesh's inference engine
     *
     * @param {string} modelName — registered model name (e.g. 'sherpa-commander')
     * @param {Object} feeds     — input tensor feeds
     * @returns {Promise<Object>} — output tensors
     */
    async runInference(modelName, feeds) {
        if (!this._inference) {
            throw new Error('ONNX inference engine not available');
        }

        return this.scheduleSherpa(async () => {
            return this._inference.run(modelName, feeds);
        });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Gossip integration — broadcast commands across mesh
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * Broadcast a game command across the mesh (for spectators, replays, etc.)
     * @param {Object} command — structured game command
     */
    broadcastCommand(command) {
        if (!this.node.gossip) return;

        this.node.gossip.spreadRumor(YAKAI_TOPICS.COMMAND_BROADCAST, {
            nodeId: this._identity?.identity?.nodeId,
            command,
            timestamp: Date.now(),
        });

        this.stats.commandsBroadcast++;
    }

    /**
     * Handle incoming gossip rumors relevant to yakai
     */
    async handleRumor(topic, data, origin) {
        // Handle base adapter rumors
        await super.handleRumor(topic, data, origin);

        switch (topic) {
            case YAKAI_TOPICS.INFERENCE_RESULT:
                this.emit('inference-result', data);
                break;
            case YAKAI_TOPICS.MODEL_STATUS:
                this.emit('model-status', data);
                break;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Internal helpers
    // ═══════════════════════════════════════════════════════════════════════

    _getHardwareInfo() {
        try {
            // Access HW detection results from accel module
            return {
                totalTops: (globalThis.__yakmesh_hw?.nvGpuTops || 0)
                    + (globalThis.__yakmesh_hw?.amdNpuTops || 0),
                gpu: globalThis.__yakmesh_hw?.nvGpu || null,
                npu: globalThis.__yakmesh_hw?.amdNpu || false,
                cpuThreads: globalThis.__yakmesh_hw?.threads || 0,
            };
        } catch {
            return { totalTops: 0, gpu: null, npu: false, cpuThreads: 0 };
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BaseAdapter required methods (yakai doesn't do traditional sync)
    // ═══════════════════════════════════════════════════════════════════════

    getSchema() {
        // yakai doesn't replicate tables — it's a consumer, not a data source
        return {};
    }

    async fetchChanges(_since) {
        // No traditional sync — yakai uses real-time ComputeScheduler + gossip
        return [];
    }

    async applyChange(_table, _record, _operation) {
        // No-op — yakai doesn't receive replicated data
    }

    getStats() {
        return {
            ...super.getStats(),
            activeSessions: this._activeSessions.size,
            inferenceRequests: this.stats.inferenceRequests,
            inferenceCompleted: this.stats.inferenceCompleted,
            inferenceFailed: this.stats.inferenceFailed,
            commandsBroadcast: this.stats.commandsBroadcast,
            capabilities: this.getCapabilities(),
        };
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Express endpoint factory — mounts yakai bridge endpoints on yakmesh HTTP
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Mount yakai bridge API endpoints on the yakmesh Express app.
 * These let yakai query capabilities and schedule work remotely.
 *
 * @param {import('express').Express} app
 * @param {YakaiAdapter} adapter
 */
export function createYakaiEndpoints(app, adapter) {
    // GET /yakai/capabilities — what's available from this node
    app.get('/yakai/capabilities', (_req, res) => {
        res.json(adapter.getCapabilities());
    });

    // GET /yakai/identity — yakmesh identity for C2C auth bridge
    app.get('/yakai/identity', (_req, res) => {
        const identity = adapter.getIdentity();
        if (!identity) {
            return res.status(503).json({ error: 'Identity not initialized' });
        }
        res.json(identity);
    });

    // POST /yakai/sign — sign a challenge with ML-DSA-65
    app.post('/yakai/sign', async (req, res) => {
        try {
            const { challenge } = req.body;
            if (!challenge) {
                return res.status(400).json({ error: 'challenge required (hex string)' });
            }
            const result = await adapter.signChallenge(challenge);
            res.json(result);
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    // GET /yakai/stats — adapter statistics
    app.get('/yakai/stats', (_req, res) => {
        res.json(adapter.getStats());
    });
}

export default YakaiAdapter;
