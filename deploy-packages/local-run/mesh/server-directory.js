// ============================================================================
// yakmesh-node — Server Directory (C2C Lighthouse)
//
// Collects heartbeats from C2C game servers on the mesh and maintains a
// live directory of active servers. Each yakmesh-node aggregates its own
// local copy from MANTRA gossip rumors (topic: 'server:heartbeat').
//
// Design principles:
//   - Node identity name only — no user-typed server names, zero moderation
//   - Gray-out over removal — stale servers degrade visually, only pruned
//     after configurable inactivity window (default 30 days)
//   - Vacation mode — servers can declare planned downtime without penalty
//   - SHERPA-style score decay for freshness tracking
//   - VIP metadata for premium server browser features
//   - Community pool balance as organic attractiveness signal
//
// Score decay model (adapted from SHERPA PeerRegistry):
//   - Fresh heartbeat → score reset to 1.0
//   - Each decay interval (2 min) → score *= 0.97
//   - Status thresholds:
//       score > 0.8  → 'online'
//       score > 0.3  → 'stale'  (grayed in browser)
//       score ≤ 0.3  → 'offline' (grayed, listed but unconnectable)
//   - Declared status ('vacation'/'maintenance') overrides score-based status
//   - Prune: entries with lastSeen older than PRUNE_DAYS are removed
// ============================================================================

import { createLogger } from '../utils/logger.js';

const log = createLogger('server-directory');

// ============================================================================
// CONSTANTS
// ============================================================================

/** Decay interval — matches C2C heartbeat interval */
const DECAY_INTERVAL_MS = 2 * 60 * 1000; // 2 minutes

/** Score multiplied by this each decay interval */
const SCORE_DECAY = 0.97;

/** Prune entries after this many days of no heartbeat */
const PRUNE_DAYS = parseInt(process.env.SERVER_PRUNE_DAYS || '30', 10);
const PRUNE_MS = PRUNE_DAYS * 24 * 60 * 60 * 1000;

/** Maximum directory entries (Sybil defense) */
const MAX_ENTRIES = 500;

/** Status thresholds */
const ONLINE_THRESHOLD = 0.8;
const OFFLINE_THRESHOLD = 0.3;

// ============================================================================
// SERVER DIRECTORY
// ============================================================================

export class ServerDirectory {
  /**
   * @type {Map<string, ServerEntry>}
   * Keyed by nodeId — one entry per yakmesh-node (one C2C per node)
   */
  #entries = new Map();

  /** @type {NodeJS.Timeout|null} */
  #decayTimer = null;

  /** @type {NodeJS.Timeout|null} */
  #beaconTimer = null;

  /** @type {string|null} Path to write static beacon file */
  #beaconPath = null;

  /**
   * @param {Object} [opts]
   * @param {string} [opts.beaconPath] — if set, writes servers.json to this path periodically
   */
  constructor(opts = {}) {
    this.#beaconPath = opts.beaconPath || null;
  }

  /**
   * Start the directory — begins score decay and optional beacon file writer.
   */
  start() {
    // Score decay loop
    this.#decayTimer = setInterval(() => this.#decayScores(), DECAY_INTERVAL_MS);
    this.#decayTimer.unref();

    // Static beacon file writer (for yakmesh.dev public bootstrap)
    if (this.#beaconPath) {
      this.#beaconTimer = setInterval(() => this.#writeBeacon(), 60_000);
      this.#beaconTimer.unref();
      log.info({ path: this.#beaconPath }, 'Server beacon writer enabled');
    }

    log.info({ maxEntries: MAX_ENTRIES, pruneDays: PRUNE_DAYS }, 'Server directory started');
  }

  /**
   * Stop the directory.
   */
  stop() {
    if (this.#decayTimer) { clearInterval(this.#decayTimer); this.#decayTimer = null; }
    if (this.#beaconTimer) { clearInterval(this.#beaconTimer); this.#beaconTimer = null; }
    log.info('Server directory stopped');
  }

  /**
   * Handle an incoming server heartbeat.
   * Called from the MANTRA rumor dispatcher when topic === 'server:heartbeat'.
   *
   * @param {Object} data — heartbeat payload (already ML-DSA-65 verified by MANTRA)
   * @param {string} origin — nodeId of the rumor origin
   */
  handleHeartbeat(data, origin) {
    const nodeId = data.nodeId || origin;
    if (!nodeId) return;

    const now = Date.now();
    const existing = this.#entries.get(nodeId);

    if (existing) {
      // Update existing entry
      existing.nodeName = data.nodeName || existing.nodeName;
      existing.declaredStatus = data.status || 'online';
      existing.playerCount = data.playerCount ?? existing.playerCount;
      existing.maxPlayers = data.maxPlayers ?? existing.maxPlayers;
      existing.version = data.version || existing.version;
      existing.uptime = data.uptime ?? existing.uptime;
      existing.governanceScore = data.governanceScore ?? existing.governanceScore;
      existing.timeSource = data.timeSource || existing.timeSource;
      existing.realms = data.realms || existing.realms;
      existing.c2cPort = data.c2cPort ?? existing.c2cPort;
      existing.vip = data.vip || existing.vip;
      existing.communityPool = data.communityPool ?? existing.communityPool;
      existing.lastSeen = now;
      existing.score = 1.0; // Reset on fresh heartbeat
      existing.heartbeatCount++;
    } else {
      // New entry — check capacity
      if (this.#entries.size >= MAX_ENTRIES) {
        this.#evictLowest();
      }

      /** @type {ServerEntry} */
      const entry = {
        nodeId,
        nodeName: data.nodeName || 'Unknown Node',
        declaredStatus: data.status || 'online',
        playerCount: data.playerCount ?? 0,
        maxPlayers: data.maxPlayers ?? null,
        version: data.version || null,
        uptime: data.uptime ?? 0,
        governanceScore: data.governanceScore ?? 1.0,
        timeSource: data.timeSource || 'system',
        realms: data.realms || [],
        c2cPort: data.c2cPort ?? null,
        vip: data.vip || {},
        communityPool: data.communityPool ?? 0,
        firstSeen: now,
        lastSeen: now,
        score: 1.0,
        heartbeatCount: 1,
      };

      this.#entries.set(nodeId, entry);
      log.info({ nodeId, nodeName: entry.nodeName }, 'New C2C server registered in directory');
    }
  }

  /**
   * Get the full directory, sorted for browser display.
   * Featured (VIP) servers pin to top, then online by playerCount, then stale/offline.
   *
   * @param {Object} [opts]
   * @param {string} [opts.status] — filter by status ('online', 'stale', 'vacation', etc.)
   * @param {number} [opts.limit] — max entries to return
   * @returns {{ servers: Array, total: number, serverTime: number }}
   */
  getDirectory({ status, limit } = {}) {
    const now = Date.now();
    let entries = [];

    for (const entry of this.#entries.values()) {
      const displayStatus = this.#resolveStatus(entry);
      const serverData = {
        nodeId: entry.nodeId,
        nodeName: entry.nodeName,
        status: displayStatus,
        playerCount: entry.playerCount,
        maxPlayers: entry.maxPlayers,
        version: entry.version,
        uptime: entry.uptime,
        governanceScore: entry.governanceScore,
        timeSource: entry.timeSource,
        realms: entry.realms,
        c2cPort: entry.c2cPort,
        vip: entry.vip,
        communityPool: entry.communityPool,
        firstSeen: entry.firstSeen,
        lastSeen: entry.lastSeen,
        score: Math.round(entry.score * 100) / 100,
      };

      if (!status || displayStatus === status) {
        entries.push(serverData);
      }
    }

    // Sort: featured first, then by status tier, then by playerCount desc
    entries.sort((a, b) => {
      // VIP featured pinned at top
      const aFeatured = a.vip?.featured ? 1 : 0;
      const bFeatured = b.vip?.featured ? 1 : 0;
      if (aFeatured !== bFeatured) return bFeatured - aFeatured;

      // Status tier: online > vacation > maintenance > stale > offline
      const statusOrder = { online: 0, vacation: 1, maintenance: 2, stale: 3, offline: 4 };
      const aOrder = statusOrder[a.status] ?? 5;
      const bOrder = statusOrder[b.status] ?? 5;
      if (aOrder !== bOrder) return aOrder - bOrder;

      // Within same status, sort by player count descending
      return (b.playerCount || 0) - (a.playerCount || 0);
    });

    const total = entries.length;
    if (limit && limit > 0) entries = entries.slice(0, limit);

    return { servers: entries, total, serverTime: now };
  }

  /**
   * Get detailed info for a single server.
   * @param {string} nodeId
   * @returns {Object|null}
   */
  getServer(nodeId) {
    const entry = this.#entries.get(nodeId);
    if (!entry) return null;

    return {
      nodeId: entry.nodeId,
      nodeName: entry.nodeName,
      status: this.#resolveStatus(entry),
      playerCount: entry.playerCount,
      maxPlayers: entry.maxPlayers,
      version: entry.version,
      uptime: entry.uptime,
      governanceScore: entry.governanceScore,
      timeSource: entry.timeSource,
      realms: entry.realms,
      c2cPort: entry.c2cPort,
      vip: entry.vip,
      communityPool: entry.communityPool,
      firstSeen: entry.firstSeen,
      lastSeen: entry.lastSeen,
      score: Math.round(entry.score * 100) / 100,
      heartbeatCount: entry.heartbeatCount,
    };
  }

  /**
   * Get directory statistics.
   * @returns {Object}
   */
  getStats() {
    let online = 0, stale = 0, vacation = 0, maintenance = 0, offline = 0;
    for (const entry of this.#entries.values()) {
      const s = this.#resolveStatus(entry);
      if (s === 'online') online++;
      else if (s === 'stale') stale++;
      else if (s === 'vacation') vacation++;
      else if (s === 'maintenance') maintenance++;
      else offline++;
    }
    return { total: this.#entries.size, online, stale, vacation, maintenance, offline };
  }

  // ==========================================================================
  // INTERNAL
  // ==========================================================================

  /**
   * Resolve display status from score + declared status.
   * Declared 'vacation'/'maintenance' override score-based status.
   * Declared 'offline' from graceful shutdown immediately grays out.
   * @param {ServerEntry} entry
   * @returns {string}
   */
  #resolveStatus(entry) {
    // Declared statuses take precedence
    if (entry.declaredStatus === 'vacation') return 'vacation';
    if (entry.declaredStatus === 'maintenance') return 'maintenance';
    if (entry.declaredStatus === 'offline') return 'offline';

    // Score-based status
    if (entry.score > ONLINE_THRESHOLD) return 'online';
    if (entry.score > OFFLINE_THRESHOLD) return 'stale';
    return 'offline';
  }

  /**
   * Apply score decay to all entries plus prune stale ones.
   */
  #decayScores() {
    const now = Date.now();
    const pruneThreshold = now - PRUNE_MS;

    for (const [nodeId, entry] of this.#entries) {
      // Prune entries that haven't been seen in PRUNE_DAYS
      if (entry.lastSeen < pruneThreshold) {
        this.#entries.delete(nodeId);
        log.info({ nodeId, nodeName: entry.nodeName, daysSinceSeen: Math.round((now - entry.lastSeen) / 86400000) },
          'Server pruned from directory (exceeded prune threshold)');
        continue;
      }

      // Apply decay
      entry.score *= SCORE_DECAY;
    }
  }

  /**
   * Evict the lowest-scored entry when at capacity.
   */
  #evictLowest() {
    let lowestId = null;
    let lowestScore = Infinity;

    for (const [nodeId, entry] of this.#entries) {
      if (entry.score < lowestScore) {
        lowestScore = entry.score;
        lowestId = nodeId;
      }
    }

    if (lowestId) {
      const evicted = this.#entries.get(lowestId);
      this.#entries.delete(lowestId);
      log.info({ nodeId: lowestId, nodeName: evicted?.nodeName, score: lowestScore },
        'Evicted lowest-scored server (directory at capacity)');
    }
  }

  /**
   * Write a static servers.json beacon file for pre-mesh bootstrapping.
   * Used by yakmesh.dev (or any node with SERVER_BEACON=true) as the
   * public entry point before a client is connected to the mesh.
   */
  async #writeBeacon() {
    if (!this.#beaconPath) return;

    try {
      const { writeFile, mkdir } = await import('node:fs/promises');
      const { dirname } = await import('node:path');

      const dir = dirname(this.#beaconPath);
      await mkdir(dir, { recursive: true });

      const directory = this.getDirectory();
      const beacon = {
        generated: Date.now(),
        version: '1.0',
        servers: directory.servers,
        total: directory.total,
      };

      await writeFile(this.#beaconPath, JSON.stringify(beacon, null, 2), 'utf8');
    } catch (err) {
      log.warn({ err: err.message }, 'Failed to write server beacon file');
    }
  }
}

// ============================================================================
// TYPE DEFINITIONS (JSDoc)
// ============================================================================

/**
 * @typedef {Object} ServerEntry
 * @property {string} nodeId — yakmesh node cryptographic identity
 * @property {string} nodeName — DOKO identity name (uneditable)
 * @property {string} declaredStatus — 'online' | 'vacation' | 'maintenance' | 'offline'
 * @property {number} playerCount — current active players
 * @property {number|null} maxPlayers — configured player cap
 * @property {string|null} version — C2C integrity hash (first 16 chars)
 * @property {number} uptime — process uptime in seconds
 * @property {number} governanceScore — ratio of clean governance events [0, 1]
 * @property {string} timeSource — MANI trust level
 * @property {string[]} realms — active realm names
 * @property {number|null} c2cPort — C2C HTTP port
 * @property {Object} vip — VIP premium metadata (featured, badge, slots, highlight)
 * @property {number} communityPool — SC balance in community pool
 * @property {number} firstSeen — timestamp of first heartbeat
 * @property {number} lastSeen — timestamp of most recent heartbeat
 * @property {number} score — freshness score [0, 1]
 * @property {number} heartbeatCount — total heartbeats received
 */

export default ServerDirectory;
