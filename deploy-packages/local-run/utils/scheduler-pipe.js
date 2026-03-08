// ============================================================================
// yakmesh-node — Named Pipe Server for ComputeScheduler + Anti-Cheat Coordination
//
// Provides cross-process access to the ComputeScheduler, identity signing,
// KARMA scoring, and integrity verification for co-located services
// (c2c, yakai) via named pipe / Unix socket.
//
// Transport: JSON-line over named pipe (\\.\pipe\yakmesh-scheduler on Windows,
//            /tmp/yakmesh-scheduler.sock on Unix/macOS)
//
// Protocol:
//   Client → Server:
//     HELLO   { op:'HELLO', pid }                      → register client
//     ADVISE  { op:'ADVISE', id, type, priority,       → get routing recommendation
//              affinity, inputSize }
//     DONE    { op:'DONE', id, device, execMs, outcome } → report task completion (stats)
//     STATUS  { op:'STATUS', id }                       → query scheduler status
//     HW      { op:'HW', id }                           → query hardware profile
//
//   Anti-Cheat ops (Pillar A — Identity + Signing):
//     SIGN    { op:'SIGN', id, message }                → sign message with ML-DSA-65
//     MINT_VISITOR { op:'MINT_VISITOR', id, label }     → create 162T visitor identity
//
//   Anti-Cheat ops (Pillar B — KARMA + Strike):
//     KARMA_CHECK  { op:'KARMA_CHECK', id, peerId }    → lookup KARMA score + tier
//     KARMA_REWARD { op:'KARMA_REWARD', id, peerId,    → reward good behavior
//                    amount, reason }
//     STRIKE_ISSUE { op:'STRIKE_ISSUE', id, peerId,    → issue strike against peer
//                    reason, evidence }
//
//   Anti-Cheat ops (Pillar C — Integrity):
//     INTEGRITY_REPORT { op:'INTEGRITY_REPORT', id,    → report C2C codebase hash
//                        codeHash, fileCount }
//
//   Server → Client:
//     WELCOME { op:'WELCOME', clientId, hw, providers } → registration accepted
//     ROUTED  { op:'ROUTED', id, device, method,        → routing recommendation
//              queueLoad }
//     ACK     { op:'ACK', id }                          → completion acknowledged
//     STATUS  { op:'STATUS', id, scheduler }             → scheduler state
//     HW      { op:'HW', id, hw }                        → hardware profile
//     SIGNED  { op:'SIGNED', id, signature, publicKey,  → signing result
//              persistentId }
//     VISITOR { op:'VISITOR', id, persistentId,         → minted visitor identity
//              publicKey }
//     KARMA   { op:'KARMA', id, peerId, score, tier }   → KARMA lookup result
//     KARMA_ACK { op:'KARMA_ACK', id, newScore }        → KARMA reward acknowledged
//     STRIKE_ACK { op:'STRIKE_ACK', id, strikes, level }→ strike issued
//     INTEGRITY_ACK { op:'INTEGRITY_ACK', id, match,   → integrity check result
//                     expected }
//     ERROR   { op:'ERROR', id, message }                → error response
//
// Tier 2 transport: ~50μs latency, no serialized inference data — coordination only.
// ============================================================================

import net from 'node:net';
import os from 'node:os';
import { existsSync, unlinkSync } from 'node:fs';
import { execFile } from 'node:child_process';

/** @type {import('./accel.js')} */
let _accel = null;

/** @type {import('../identity/node-key.js').NodeIdentity|null} */
let _identity = null;

/** @type {import('../security/karma-rate-limiter.js').KarmaRateLimiter|null} */
let _karmaLimiter = null;

/** @type {import('../security/strike-system.js').StrikeRevocationBridge|null} */
let _strikeBridge = null;

/** @type {Object|null} — oracle instance for integrity checks */
let _oracle = null;

/** @type {import('../gossip/protocol.js').GossipProtocol|null} */
let _gossip = null;

/** @type {Object|null} - ServerDirectory for local heartbeat delivery */
let _serverDirectory = null;

/** @type {Map<string, { persistentId: string, publicKey: string, createdAt: number }>} */
const _visitorIdentities = new Map();

const PIPE_PATH = os.platform() === 'win32'
    ? '\\\\.\\pipe\\yakmesh-scheduler'
    : '/tmp/yakmesh-scheduler.sock';

/** @type {net.Server|null} */
let _server = null;

/** @type {Map<number, { id: number, socket: net.Socket, buffer: string, pid: number|null }>} */
const _clients = new Map();
let _clientCounter = 0;
let _log = { info: console.log, warn: console.warn, error: console.error, debug: () => { } };

// ============================================================================
// SERVER LIFECYCLE
// ============================================================================

/**
 * Start the named pipe server for scheduler + anti-cheat coordination.
 *
 * @param {Object} opts
 * @param {Object} opts.accel     — the accel module (scheduler, HW, Priority, etc.)
 * @param {Object} [opts.identity] — NodeIdentity instance for signing ops
 * @param {Object} [opts.karmaLimiter] — KarmaRateLimiter for KARMA ops
 * @param {Object} [opts.strikeBridge] — StrikeRevocationBridge for strike ops
 * @param {Object} [opts.oracle]  — Validation oracle for integrity checks
 * @param {Object} [opts.log]     — logger instance
 * @param {string} [opts.path]    — override pipe path (for testing)
 * @returns {Promise<{ path: string, listening: boolean }>}
 */
export async function startPipeServer({ accel, identity, karmaLimiter, strikeBridge, oracle, log, path } = {}) {
    if (_server) return { path: PIPE_PATH, listening: true };

    _accel = accel;
    if (identity) _identity = identity;
    if (karmaLimiter) _karmaLimiter = karmaLimiter;
    if (strikeBridge) _strikeBridge = strikeBridge;
    if (oracle) _oracle = oracle;
    if (log) _log = log;
    const pipePath = path || PIPE_PATH;

    // Clean up stale socket file on Unix
    if (os.platform() !== 'win32' && existsSync(pipePath)) {
        try { unlinkSync(pipePath); } catch { /* ignore */ }
    }

    return new Promise((resolve, reject) => {
        _server = net.createServer(_handleConnection);

        _server.on('error', (err) => {
            _log.error(`Scheduler pipe error: ${err.message}`);
            if (err.code === 'EADDRINUSE') {
                // Another instance has the pipe — not fatal, just skip
                _log.warn(`Scheduler pipe ${pipePath} already in use — running without pipe coordination`);
                _server = null;
                resolve({ path: pipePath, listening: false });
            } else {
                reject(err);
            }
        });

        _server.listen(pipePath, () => {
            _log.info(`Scheduler pipe listening: ${pipePath} (${_accel.HW.totalTops} TOPS available)`);
            resolve({ path: pipePath, listening: true });
        });
    });
}

/**
 * Stop the pipe server and disconnect all clients.
 */
export async function stopPipeServer() {
    if (!_server) return;
    for (const client of _clients.values()) {
        client.socket.destroy();
    }
    _clients.clear();

    return new Promise((resolve) => {
        _server.close(() => {
            _server = null;
            _log.info('Scheduler pipe closed');

            // Clean up socket file on Unix
            const pipePath = PIPE_PATH;
            if (os.platform() !== 'win32' && existsSync(pipePath)) {
                try { unlinkSync(pipePath); } catch { /* ignore */ }
            }
            resolve();
        });
    });
}

/**
 * Check if the pipe server is running.
 */
export function isPipeServerRunning() {
    return !!_server;
}

/**
 * Get the pipe path (for passing to child processes as env var).
 */
export function getPipePath() {
    return PIPE_PATH;
}

// ============================================================================
// CONNECTION HANDLER
// ============================================================================

function _handleConnection(socket) {
    const clientId = ++_clientCounter;
    const client = { id: clientId, socket, buffer: '', pid: null };
    _clients.set(clientId, client);

    _log.debug(`Pipe client ${clientId} connected`);

    socket.on('data', (data) => {
        client.buffer += data.toString('utf8');

        // Process complete JSON lines
        let newlineIdx;
        while ((newlineIdx = client.buffer.indexOf('\n')) !== -1) {
            const line = client.buffer.slice(0, newlineIdx).trim();
            client.buffer = client.buffer.slice(newlineIdx + 1);
            if (line) {
                try {
                    _handleMessage(client, JSON.parse(line));
                } catch (err) {
                    _send(client, { op: 'ERROR', id: null, message: `Parse error: ${err.message}` });
                }
            }
        }
    });

    socket.on('close', () => {
        _clients.delete(clientId);
        _log.debug(`Pipe client ${clientId} disconnected`);
    });

    socket.on('error', (err) => {
        if (err.code !== 'ECONNRESET' && err.code !== 'EPIPE') {
            _log.warn(`Pipe client ${clientId} error: ${err.message}`);
        }
        _clients.delete(clientId);
    });
}

// ============================================================================
// MESSAGE HANDLERS
// ============================================================================

async function _handleMessage(client, msg) {
    switch (msg.op) {
        case 'HELLO':
            _handleHello(client, msg);
            break;
        case 'ADVISE':
            await _handleAdvise(client, msg);
            break;
        case 'DONE':
            _handleDone(client, msg);
            break;
        case 'STATUS':
            _handleStatus(client, msg);
            break;
        case 'HW':
            _handleHW(client, msg);
            break;
        // ── Anti-Cheat: Pillar A — Identity + Signing ──
        case 'SIGN':
            _handleSign(client, msg);
            break;
        case 'MINT_VISITOR':
            _handleMintVisitor(client, msg);
            break;
        // ── Anti-Cheat: Pillar B — KARMA + Strike ──
        case 'KARMA_CHECK':
            _handleKarmaCheck(client, msg);
            break;
        case 'KARMA_REWARD':
            _handleKarmaReward(client, msg);
            break;
        case 'STRIKE_ISSUE':
            _handleStrikeIssue(client, msg);
            break;
        // ── Anti-Cheat: Pillar C — Integrity ──
        case 'INTEGRITY_REPORT':
            _handleIntegrityReport(client, msg);
            break;
        // ── Dynamis: Model Retraining ──
        case 'TRAIN_REQUEST':
            _handleTrainRequest(client, msg);
            break;
        // ── Governance + Server Lighthouse ──
        case 'GOVERNANCE_EVENT':
            _handleGovernanceEvent(client, msg);
            break;
        case 'SERVER_HEARTBEAT':
            _handleServerHeartbeat(client, msg);
            break;
        default:
            _send(client, { op: 'ERROR', id: msg.id || null, message: `Unknown op: ${msg.op}` });
    }
}

function _handleHello(client, msg) {
    client.pid = msg.pid || null;
    const hw = {
        cpu: _accel.HW.cpuModel,
        arch: _accel.HW.cpuArch,
        threads: _accel.HW.threads,
        gpu: _accel.HW.nvGpu ? { name: _accel.HW.nvGpuName, vram: _accel.HW.nvGpuVRAM, tops: _accel.HW.nvGpuTops } : null,
        npu: _accel.HW.amdNpu ? { tops: _accel.HW.amdNpuTops } : null,
        totalTops: _accel.HW.totalTops,
        providers: _accel.HW.onnxProviders,
    };

    const identityInfo = _identity ? {
        nodeId: _identity.identity?.nodeId || null,
        nodeName: _identity.identity?.name || null,
        persistentId: _identity.identity?.persistentId || null,
    } : {};

    _send(client, {
        op: 'WELCOME',
        clientId: client.id,
        hw,
        providers: _accel.HW.onnxProviders,
        ...identityInfo,
    });

    _log.info(`Pipe client ${client.id} registered (pid: ${client.pid})`);
}

async function _handleAdvise(client, msg) {
    if (!_accel.scheduler) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'Scheduler not initialized' });
        return;
    }

    try {
        const result = await _accel.scheduler.advise({
            type: msg.type || 'advisory',
            typeId: msg.typeId || 0,
            priority: _accel.Priority[msg.priority] ?? _accel.Priority.NORMAL,
            affinity: _accel.Affinity[msg.affinity] ?? _accel.Affinity.EITHER,
            inputSize: msg.inputSize || 0,
        });

        _send(client, {
            op: 'ROUTED',
            id: msg.id,
            device: result.device,
            method: result.method,
            queueLoad: result.queueLoad,
        });
    } catch (err) {
        _send(client, { op: 'ERROR', id: msg.id, message: err.message });
    }
}

function _handleDone(client, msg) {
    // Report task completion back to scheduler for stats tracking.
    // Updates the scheduler's latency averages and ML training data.
    if (_accel.scheduler && msg.device && msg.execMs != null) {
        const device = msg.device;
        // Update scheduler latency tracking (exposed via _updateAvgLatency)
        // This is informational — the scheduler tracks its own tasks, but
        // cross-process outcomes help the ML model learn about real-world latency.
        _accel.scheduler._stats.totalCompleted++;
    }

    _send(client, { op: 'ACK', id: msg.id });
}

function _handleStatus(client, msg) {
    const status = _accel.scheduler
        ? _accel.scheduler.getStatus()
        : { initialized: false };

    _send(client, { op: 'STATUS', id: msg.id, scheduler: status });
}

function _handleHW(client, msg) {
    const hw = {
        cpu: _accel.HW.cpuModel,
        arch: _accel.HW.cpuArch,
        threads: _accel.HW.threads,
        simd: { avx512: _accel.HW.avx512, vaes: _accel.HW.vaes, shaNI: _accel.HW.shaNI },
        gpu: _accel.HW.nvGpu ? { name: _accel.HW.nvGpuName, vram: _accel.HW.nvGpuVRAM, tops: _accel.HW.nvGpuTops } : null,
        npu: _accel.HW.amdNpu ? { tops: _accel.HW.amdNpuTops } : null,
        totalTops: _accel.HW.totalTops,
        providers: _accel.HW.onnxProviders,
    };

    _send(client, { op: 'HW', id: msg.id, hw });
}

// ============================================================================
// ANTI-CHEAT HANDLERS — Pillar A: Identity + Signing
// ============================================================================

/**
 * SIGN — sign a message using the node's ML-DSA-65 key.
 * Returns { signature, publicKey, persistentId } so C2C can verify actions
 * were authorized by the local yakmesh node.
 *
 * msg: { op:'SIGN', id, message: string }
 */
function _handleSign(client, msg) {
    if (!_identity || !_identity.identity) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'Identity not initialized' });
        return;
    }
    if (!msg.message || typeof msg.message !== 'string') {
        _send(client, { op: 'ERROR', id: msg.id, message: 'message (string) required' });
        return;
    }

    try {
        const signature = _identity.sign(msg.message);
        _send(client, {
            op: 'SIGNED',
            id: msg.id,
            signature,
            publicKey: _identity.identity.publicKey,
            persistentId: _identity.identity.persistentId || null,
        });
    } catch (err) {
        _send(client, { op: 'ERROR', id: msg.id, message: `Sign failed: ${err.message}` });
    }
}

/**
 * MINT_VISITOR — create a transient 162T identity for an external player
 * who connects to C2C without a local yakmesh node. The visitor identity
 * is managed server-side (no browser key storage).
 *
 * msg: { op:'MINT_VISITOR', id, label?: string }
 */
function _handleMintVisitor(client, msg) {
    if (!_identity || !_identity.identity) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'Identity not initialized' });
        return;
    }

    try {
        // Import ternary addressing for visitor ID derivation
        const label = msg.label || `visitor-${Date.now()}`;
        const visitorSeed = `visitor:${label}:${Date.now()}:${Math.random()}`;

        // Derive a visitor persistent ID using SHA3-256 of the seed + node context
        // This is NOT a full node identity — it's a lightweight 162T address
        // for tracking visitor actions within C2C
        const { sha3_256: sha3 } = _accel;
        const hashBytes = sha3(new TextEncoder().encode(visitorSeed));
        const visitorHash = Buffer.from(hashBytes).toString('hex');

        // Generate a truncated 162T-style ID: "yak-v-" prefix + first 24 hex chars
        const persistentId = `yak-v-${visitorHash.slice(0, 24)}`;

        // Store in visitor map for session lifetime
        _visitorIdentities.set(persistentId, {
            persistentId,
            publicKey: _identity.identity.publicKey, // signed by host node
            createdAt: Date.now(),
        });

        _send(client, {
            op: 'VISITOR',
            id: msg.id,
            persistentId,
            publicKey: _identity.identity.publicKey,
            hostNodeId: _identity.identity.nodeId,
        });

        _log.info(`Minted visitor identity: ${persistentId} (label: ${label})`);
    } catch (err) {
        _send(client, { op: 'ERROR', id: msg.id, message: `Mint visitor failed: ${err.message}` });
    }
}

// ============================================================================
// ANTI-CHEAT HANDLERS — Pillar B: KARMA + Strike
// ============================================================================

/**
 * KARMA_CHECK — lookup KARMA score and tier for a peer.
 * msg: { op:'KARMA_CHECK', id, peerId }
 */
function _handleKarmaCheck(client, msg) {
    if (!_karmaLimiter) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'KARMA rate limiter not available' });
        return;
    }
    if (!msg.peerId) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'peerId required' });
        return;
    }

    try {
        const result = _karmaLimiter.checkLimit(msg.peerId, 0); // 0 cost = info-only
        _send(client, {
            op: 'KARMA',
            id: msg.id,
            peerId: msg.peerId,
            score: result.remaining, // tokens remaining = effective capacity
            tier: result.tier,
        });
    } catch (err) {
        _send(client, { op: 'ERROR', id: msg.id, message: `KARMA check failed: ${err.message}` });
    }
}

/**
 * KARMA_REWARD — reward a peer for good behavior (bidirectional KARMA).
 * Positive KARMA accrual: honest play, sportsmanship, uptime.
 *
 * msg: { op:'KARMA_REWARD', id, peerId, amount: number, reason: string }
 */
function _handleKarmaReward(client, msg) {
    if (!_karmaLimiter) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'KARMA rate limiter not available' });
        return;
    }
    if (!msg.peerId || !msg.reason) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'peerId and reason required' });
        return;
    }

    try {
        const amount = Math.min(Math.max(msg.amount || 1, 0.1), 10); // clamp [0.1, 10]

        // Emit reward event — the KARMA system can listen and update scores
        _karmaLimiter.emit('karma:reward', {
            peerId: msg.peerId,
            amount,
            reason: msg.reason,
            source: `pipe-client-${client.id}`,
            timestamp: Date.now(),
        });

        _send(client, {
            op: 'KARMA_ACK',
            id: msg.id,
            peerId: msg.peerId,
            amount,
            reason: msg.reason,
        });

        _log.debug(`KARMA reward: ${msg.peerId.slice(0, 16)}... +${amount} (${msg.reason})`);
    } catch (err) {
        _send(client, { op: 'ERROR', id: msg.id, message: `KARMA reward failed: ${err.message}` });
    }
}

/**
 * STRIKE_ISSUE — issue a strike against a peer for cheating/abuse.
 * msg: { op:'STRIKE_ISSUE', id, peerId, reason, evidence? }
 */
function _handleStrikeIssue(client, msg) {
    if (!_strikeBridge) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'Strike system not available' });
        return;
    }
    if (!msg.peerId || !msg.reason) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'peerId and reason required' });
        return;
    }

    try {
        const result = _strikeBridge.strikeRegistry?.issueStrike?.({
            hardwareFingerprint: msg.peerId, // C2C uses persistentId as fingerprint
            nodeId: msg.peerId,
            reason: msg.reason,
            evidence: msg.evidence || {},
        });

        _send(client, {
            op: 'STRIKE_ACK',
            id: msg.id,
            peerId: msg.peerId,
            strikes: result?.strikes ?? 0,
            level: result?.level ?? 'UNKNOWN',
            consequence: result?.consequence ?? null,
        });

        _log.warn(`Strike issued: ${msg.peerId.slice(0, 16)}... — ${msg.reason}`);
    } catch (err) {
        _send(client, { op: 'ERROR', id: msg.id, message: `Strike failed: ${err.message}` });
    }
}

// ============================================================================
// ANTI-CHEAT HANDLERS — Pillar C: Integrity
// ============================================================================

/**
 * INTEGRITY_REPORT — C2C reports its codebase hash at startup.
 * The yakmesh oracle can cross-check this against expected values.
 *
 * msg: { op:'INTEGRITY_REPORT', id, codeHash, fileCount }
 */
function _handleIntegrityReport(client, msg) {
    if (!msg.codeHash) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'codeHash required' });
        return;
    }

    const report = {
        clientId: client.id,
        pid: client.pid,
        codeHash: msg.codeHash,
        fileCount: msg.fileCount || 0,
        receivedAt: Date.now(),
    };

    // Store the latest integrity report for this client
    client.integrityReport = report;

    // If oracle is available, cross-check against known C2C hash
    let match = null;
    let expected = null;
    if (_oracle) {
        expected = _oracle.selfHash || null;
        // C2C has its own hash — we just record it for audit.
        // Full match check would require C2C's expected hash from config.
        match = 'recorded'; // Not verified (C2C uses different codebase)
    }

    _send(client, {
        op: 'INTEGRITY_ACK',
        id: msg.id,
        match,
        expected,
        recorded: true,
    });

    _log.info(`Integrity report from client ${client.id}: hash=${msg.codeHash.slice(0, 16)}... files=${msg.fileCount}`);
}

// ============================================================================
// DYNAMIS: Model Retraining via Go Binary
// ============================================================================

/** Path to the compiled Dynamis training binary */
const DYNAMIS_TRAIN_BIN = os.platform() === 'win32'
    ? 'dynamis-train.exe'
    : 'dynamis-train';

/** Flag to prevent concurrent retraining */
let _trainInProgress = false;

/**
 * TRAIN_REQUEST — C2C requests a Dynamis model retrain.
 * Spawns the Go training binary at LOW priority through the ComputeScheduler.
 *
 * msg: { op:'TRAIN_REQUEST', id, dataPath, outputPath }
 */
function _handleTrainRequest(client, msg) {
    if (!msg.dataPath || !msg.outputPath) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'dataPath and outputPath required' });
        return;
    }

    if (_trainInProgress) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'Training already in progress' });
        return;
    }

    // Ask ComputeScheduler for routing advice
    let device = 'cpu';
    if (_accel.scheduler) {
        try {
            // Check if a mesh peer has better hardware for this task
            const best = _accel.scheduler.findBestPeer({
                affinity: _accel.Affinity.GPU_PREFERRED,
                priority: _accel.Priority.LOW,
            });
            if (best.nodeId) {
                // A remote peer is more capable — signal routing
                _send(client, {
                    op: 'ROUTE_TO_PEER',
                    id: msg.id,
                    nodeId: best.nodeId,
                    totalTops: best.totalTops,
                    reason: best.reason,
                });
                _trainInProgress = false;
                return;
            }

            // Local execution — advisory routing for device selection
            const advice = _accel.scheduler.advise({
                type: 'training',
                typeId: 0,
                priority: _accel.Priority.LOW,
                affinity: _accel.Affinity.GPU_PREFERRED,
                inputSize: 0,
            });
            if (advice?.device) device = advice.device;
        } catch { /* scheduler unavailable — default to cpu */ }
    }

    _trainInProgress = true;
    _send(client, { op: 'ACK', id: msg.id, device, status: 'training_started' });

    _log.info(`Dynamis retrain started: data=${msg.dataPath} output=${msg.outputPath} device=${device}`);

    const args = [
        '-data', msg.dataPath,
        '-output', msg.outputPath,
        '-device', device,
    ];

    const t0 = Date.now();
    execFile(DYNAMIS_TRAIN_BIN, args, { timeout: 300_000 }, (err, stdout, stderr) => {
        _trainInProgress = false;
        const execMs = Date.now() - t0;

        if (err) {
            _log.warn(`Dynamis retrain failed (${execMs}ms): ${err.message}`);
            // Push failure notification to the requesting client
            _send(client, {
                op: 'TRAIN_FAILED',
                error: err.message,
                stderr: stderr?.slice(0, 500) || '',
                execMs,
            });
            return;
        }

        _log.info(`Dynamis retrain completed (${execMs}ms): ${msg.outputPath}`);

        // Report completion to scheduler for stats
        if (_accel.scheduler) {
            _accel.scheduler._stats.totalCompleted++;
        }

        // Push completion notification to the requesting client
        _send(client, {
            op: 'TRAIN_COMPLETE',
            outputPath: msg.outputPath,
            execMs,
            stdout: stdout?.slice(0, 500) || '',
        });
    });
}

// ============================================================================
// WIRE FORMAT
// ============================================================================

function _send(client, msg) {
    try {
        client.socket.write(JSON.stringify(msg) + '\n');
    } catch {
        // Client disconnected — clean up
        _clients.delete(client.id);
    }
}

/**
 * Get the map of minted visitor identities (for API/diagnostics).
 * @returns {Map<string, { persistentId: string, publicKey: string, createdAt: number }>}
 */
export function getVisitorIdentities() {
    return _visitorIdentities;
}

/**
 * Upgrade an already-running pipe server with anti-cheat capabilities.
 * Called after identity/KARMA/oracle/strike systems are initialized
 * (which happens after the pipe server is started).
 *
 * @param {Object} opts
 * @param {Object} [opts.identity]     — NodeIdentity instance
 * @param {Object} [opts.karmaLimiter] — KarmaRateLimiter instance
 * @param {Object} [opts.strikeBridge] — StrikeRevocationBridge instance
 * @param {Object} [opts.oracle]       — Validation oracle instance
 */
export function upgradePipeAntiCheat({ identity, karmaLimiter, strikeBridge, oracle, gossip, serverDirectory } = {}) {
    if (identity) _identity = identity;
    if (karmaLimiter) _karmaLimiter = karmaLimiter;
    if (strikeBridge) _strikeBridge = strikeBridge;
    if (oracle) _oracle = oracle;
    if (gossip) _gossip = gossip;
    if (serverDirectory) _serverDirectory = serverDirectory;

    const capabilities = [];
    if (_identity) capabilities.push('SIGN');
    if (_karmaLimiter) capabilities.push('KARMA');
    if (_strikeBridge) capabilities.push('STRIKE');
    if (_oracle) capabilities.push('INTEGRITY');
    if (_gossip) capabilities.push('GOSSIP');

    if (capabilities.length > 0) {
        _log.info(`Pipe anti-cheat upgraded: ${capabilities.join(', ')}`);
    }
}

// ============================================================================
// GOVERNANCE + SERVER LIGHTHOUSE HANDLERS
// ============================================================================

/**
 * Handle GOVERNANCE_EVENT — broadcast governance transparency event to the mesh.
 * C2C sends these when admin actions occur; we spread them as signed gossip rumors.
 */
function _handleGovernanceEvent(client, msg) {
    if (!_gossip) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'Gossip not available yet' });
        return;
    }

    _gossip.spreadRumor('governance:event', {
        eventType: msg.eventType,
        actorRole: msg.actorRole,
        action: msg.action,
        summary: msg.summary,
        details: msg.details || {},
        timestamp: Date.now(),
    });

    _send(client, { op: 'ACK', id: msg.id });
    _log.debug(`Governance event broadcast: ${msg.action}`);
}

/**
 * Handle SERVER_HEARTBEAT — broadcast C2C server presence to the mesh.
 * The heartbeat is spread as a signed gossip rumor with topic 'server:heartbeat'.
 * Other yakmesh nodes collect these into their local server directories.
 */
function _handleServerHeartbeat(client, msg) {
    if (!_gossip) {
        _send(client, { op: 'ERROR', id: msg.id, message: 'Gossip not available yet' });
        return;
    }

    // Inject the node's cryptographic identity — C2C cannot spoof these
    const identity = _identity?.getPublicIdentity?.() || {};
    const heartbeat = {
        nodeId: identity.nodeId || 'unknown',
        nodeName: identity.name || 'Unknown Node',
        status: msg.status || 'online',
        playerCount: msg.playerCount ?? 0,
        maxPlayers: msg.maxPlayers ?? null,
        version: msg.version || null,
        uptime: msg.uptime ?? 0,
        governanceScore: msg.governanceScore ?? 1.0,
        timeSource: msg.timeSource || 'system',
        realms: msg.realms || [],
        c2cPort: msg.c2cPort ?? null,
        vip: msg.vip || {},
        communityPool: msg.communityPool ?? 0,
        timestamp: Date.now(),
    };

    _gossip.spreadRumor('server:heartbeat', heartbeat);

    // Deliver directly to local ServerDirectory — spreadRumor only emits
    // to remote peers; solo nodes with no peers would never see their own heartbeat.
    _serverDirectory?.handleHeartbeat(heartbeat, heartbeat.nodeId);

    _send(client, { op: 'ACK', id: msg.id });
    _log.debug({ nodeId: heartbeat.nodeId, players: heartbeat.playerCount }, 'Server heartbeat broadcast');
}

export default { startPipeServer, stopPipeServer, isPipeServerRunning, getPipePath, getVisitorIdentities, upgradePipeAntiCheat };
