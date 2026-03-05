/**
 * Mesh Profile API
 * 
 * Unified user profiles replicated across all yakmesh nodes via the
 * Lantern Replication Engine + MANTRA gossip protocol.
 * 
 * Profiles are keyed on persistentId and contain display preferences,
 * avatar selection, theme colors, bio, and optional QRL address.
 * Each update is ML-DSA-65 signed by the identity owner.
 * 
 * Architecture:
 *   yakapp / c2c / dashboard  ─── HTTP ───┐
 *                                          ├── Profile API ── replication + gossip
 *   other mesh nodes          ── gossip ──┘
 * 
 * @module server/profile-api
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { Router } from 'express';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createLogger } from '../utils/logger.js';
import { generateIdenticon } from './identicon.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const log = createLogger('server:profile');

// Load avatar presets once at startup
let AVATAR_PRESETS = { version: 1, categories: [], presets: [] };
try {
    const raw = readFileSync(join(__dirname, 'avatar-presets.json'), 'utf-8');
    AVATAR_PRESETS = JSON.parse(raw);
    log.info(`Loaded ${AVATAR_PRESETS.presets.length} avatar presets`);
} catch (e) {
    log.warn('Failed to load avatar presets, using empty gallery', { error: e.message });
}

/**
 * Maximum field lengths to prevent abuse
 */
const LIMITS = {
    displayName: 32,
    bio: 280,
    statusMessage: 100,
    qrl_address: 79,    // QRL addresses are 79 chars
    theme_color: 7,     // #RRGGBB
    theme_mode: 5,      // light / dark
};

/**
 * Default profile fields
 */
function defaultProfile(persistentId) {
    return {
        persistentId,
        displayName: '',
        bio: '',
        statusMessage: '',
        avatar_type: 'identicon',  // 'identicon' | 'preset'
        avatar_id: null,           // preset id (null = use identicon)
        theme_color: '#6366f1',    // default indigo
        theme_mode: 'dark',
        premium_effects: '[]',     // JSON array of unlocked effect ids
        tier: 'free',
        qrl_address: '',
        preferences: '{}',        // JSON blob for app-specific prefs
        updated_at: Date.now(),
    };
}

/**
 * Sanitize and validate profile fields from user input.
 * Returns only allowed fields, trimmed and length-limited.
 */
function sanitizeProfile(input) {
    const clean = {};

    if (input.displayName != null) {
        clean.displayName = String(input.displayName).trim().slice(0, LIMITS.displayName);
    }
    if (input.bio != null) {
        clean.bio = String(input.bio).trim().slice(0, LIMITS.bio);
    }
    if (input.statusMessage != null) {
        clean.statusMessage = String(input.statusMessage).trim().slice(0, LIMITS.statusMessage);
    }
    if (input.avatar_type != null) {
        const t = String(input.avatar_type);
        if (t === 'identicon' || t === 'preset') clean.avatar_type = t;
    }
    if (input.avatar_id != null) {
        const id = String(input.avatar_id).trim();
        // Validate it's a real preset
        if (AVATAR_PRESETS.presets.some(p => p.id === id)) {
            clean.avatar_id = id;
        }
    }
    if (input.theme_color != null) {
        const c = String(input.theme_color).trim();
        if (/^#[0-9a-fA-F]{6}$/.test(c)) clean.theme_color = c;
    }
    if (input.theme_mode != null) {
        const m = String(input.theme_mode);
        if (m === 'light' || m === 'dark') clean.theme_mode = m;
    }
    if (input.qrl_address != null) {
        const addr = String(input.qrl_address).trim();
        if (addr.length <= LIMITS.qrl_address) clean.qrl_address = addr;
    }
    if (input.preferences != null) {
        // Must be valid JSON, max 2KB
        try {
            const s = typeof input.preferences === 'string'
                ? input.preferences
                : JSON.stringify(input.preferences);
            JSON.parse(s); // validate
            if (s.length <= 2048) clean.preferences = s;
        } catch { /* ignore invalid */ }
    }

    return clean;
}

/**
 * Create the user_profiles table in the replication database if it doesn't exist.
 */
export function ensureProfileTable(replication) {
    if (!replication?.db) return;
    try {
        replication.db.run(`
      CREATE TABLE IF NOT EXISTS user_profiles (
        persistentId TEXT PRIMARY KEY,
        displayName TEXT DEFAULT '',
        bio TEXT DEFAULT '',
        statusMessage TEXT DEFAULT '',
        avatar_type TEXT DEFAULT 'identicon',
        avatar_id TEXT DEFAULT NULL,
        theme_color TEXT DEFAULT '#6366f1',
        theme_mode TEXT DEFAULT 'dark',
        premium_effects TEXT DEFAULT '[]',
        tier TEXT DEFAULT 'free',
        qrl_address TEXT DEFAULT '',
        preferences TEXT DEFAULT '{}',
        updated_at INTEGER NOT NULL,
        node_id TEXT NOT NULL
      )
    `);
        replication.db.run(`
      CREATE INDEX IF NOT EXISTS idx_profiles_updated
      ON user_profiles(updated_at)
    `);
        log.info('user_profiles table ensured');
    } catch (e) {
        log.warn('Failed to create user_profiles table', { error: e.message });
    }
}

/**
 * Get a profile from the replication database.
 * Returns the profile object or null.
 */
function getProfile(replication, persistentId) {
    if (!replication?.db) return null;
    try {
        const stmt = replication.db.prepare(
            'SELECT * FROM user_profiles WHERE persistentId = ?'
        );
        stmt.bind([persistentId]);
        if (stmt.step()) {
            const cols = stmt.getColumnNames();
            const vals = stmt.get();
            stmt.free();
            const row = {};
            cols.forEach((c, i) => { row[c] = vals[i]; });
            return row;
        }
        stmt.free();
    } catch (e) {
        log.warn('Failed to get profile', { persistentId: String(persistentId || '').slice(0, 12), error: e.message });
    }
    return null;
}

/**
 * Upsert a profile into the replication database.
 */
function upsertProfile(replication, profile, nodeId) {
    if (!replication?.db) return false;
    try {
        const fields = defaultProfile(profile.persistentId);
        // Merge with existing
        const existing = getProfile(replication, profile.persistentId) || {};
        const merged = { ...fields, ...existing, ...profile, node_id: nodeId, updated_at: Date.now() };

        replication.db.run(`
      INSERT OR REPLACE INTO user_profiles 
        (persistentId, displayName, bio, statusMessage, avatar_type, avatar_id,
         theme_color, theme_mode, premium_effects, tier, qrl_address, preferences,
         updated_at, node_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
            merged.persistentId, merged.displayName, merged.bio, merged.statusMessage,
            merged.avatar_type, merged.avatar_id, merged.theme_color, merged.theme_mode,
            merged.premium_effects, merged.tier, merged.qrl_address, merged.preferences,
            merged.updated_at, merged.node_id,
        ]);
        // Save to disk
        if (replication._saveDb) replication._saveDb();
        return true;
    } catch (e) {
        log.error('Failed to upsert profile', { error: e.message });
        return false;
    }
}

/**
 * Create the Profile API router.
 * 
 * @param {Object} params
 * @param {Object} params.replication - ReplicationEngine instance
 * @param {Object} params.gossip - GossipProtocol instance
 * @param {Object} params.identity - NodeIdentity instance
 * @param {Function} params.writeLimiter - Express rate limiter for writes
 * @returns {Router}
 */
export function createProfileAPI({ replication, gossip, identity, writeLimiter }) {
    const router = Router();
    const nodeId = identity.identity.nodeId;
    const persistentId = identity.getPersistentId();

    // ═══════════════════════════════════════════════════════════════════════════
    // GET /profile — Own profile
    // ═══════════════════════════════════════════════════════════════════════════
    router.get('/', (req, res) => {
        const profile = getProfile(replication, persistentId) || defaultProfile(persistentId);
        res.json({ ok: true, profile });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // GET /profile/presets — Avatar preset gallery
    // ═══════════════════════════════════════════════════════════════════════════
    router.get('/presets', (req, res) => {
        const tier = req.query.tier; // optional filter: 'free' or 'premium'
        let presets = AVATAR_PRESETS.presets;
        if (tier === 'free' || tier === 'premium') {
            presets = presets.filter(p => p.tier === tier);
        }
        res.json({
            ok: true,
            categories: AVATAR_PRESETS.categories,
            presets,
            total: presets.length,
        });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // GET /profile/avatar/:persistentId — Serve avatar image
    // Returns PNG identicon or redirects to preset asset
    // ═══════════════════════════════════════════════════════════════════════════
    router.get('/avatar/:pid', (req, res) => {
        const pid = req.params.pid;
        const profile = getProfile(replication, pid);

        if (profile && profile.avatar_type === 'preset' && profile.avatar_id) {
            // Find the preset and redirect to its asset path
            const preset = AVATAR_PRESETS.presets.find(p => p.id === profile.avatar_id);
            if (preset) {
                return res.redirect(preset.path);
            }
        }

        // Default: generate identicon
        try {
            const png = generateIdenticon(pid || 'anonymous');
            res.set('Content-Type', 'image/png');
            res.set('Cache-Control', 'public, max-age=86400');
            res.send(png);
        } catch (e) {
            log.error('Identicon generation failed', { error: e.message });
            res.status(500).json({ ok: false, error: 'Avatar generation failed' });
        }
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // GET /profile/:persistentId — View any profile
    // ═══════════════════════════════════════════════════════════════════════════
    router.get('/:pid', (req, res) => {
        const pid = req.params.pid;
        const profile = getProfile(replication, pid);
        if (!profile) {
            return res.status(404).json({ ok: false, error: 'Profile not found' });
        }
        // Strip sensitive fields for public view
        const { node_id, preferences, ...publicProfile } = profile;
        res.json({ ok: true, profile: publicProfile });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // POST /profile — Update own profile (localhost-only, ML-DSA-65 signed)
    // ═══════════════════════════════════════════════════════════════════════════
    router.post('/', writeLimiter, (req, res) => {
        // Only the local node can update its own profile
        const remoteIp = req.ip || req.connection?.remoteAddress || '';
        const isLocal = remoteIp === '127.0.0.1' || remoteIp === '::1' || remoteIp === '::ffff:127.0.0.1';
        if (!isLocal) {
            return res.status(403).json({ ok: false, error: 'Profile updates are localhost-only' });
        }

        const fields = sanitizeProfile(req.body);
        if (Object.keys(fields).length === 0) {
            return res.status(400).json({ ok: false, error: 'No valid fields provided' });
        }

        // ── Premium preset gating ──────────────────────────────────────────
        // If the user picks a premium avatar preset, verify their tier allows it
        if (fields.avatar_id) {
            const preset = AVATAR_PRESETS.presets.find(p => p.id === fields.avatar_id);
            if (preset && preset.tier === 'premium') {
                const current = getProfile(replication, persistentId);
                const currentTier = current?.tier || 'free';
                if (currentTier === 'free') {
                    return res.status(403).json({
                        ok: false,
                        error: 'Premium avatar requires Commander or higher tier',
                        requiredTier: 'commander',
                    });
                }
            }
        }

        fields.persistentId = persistentId;

        // Upsert locally
        const ok = upsertProfile(replication, fields, nodeId);
        if (!ok) {
            return res.status(500).json({ ok: false, error: 'Failed to save profile' });
        }

        // Record in replication log for Lantern sync
        replication.recordChange('user_profiles', persistentId, 'UPSERT', fields);

        // Gossip the update to the mesh
        const fullProfile = getProfile(replication, persistentId);
        const payload = JSON.stringify(fullProfile);
        const signature = identity.sign(payload);

        gossip.spreadRumor('profile:update', {
            profile: fullProfile,
            signature,
            nodeId,
        });

        log.info('Profile updated and gossiped', { persistentId: persistentId.slice(0, 12) });
        res.json({ ok: true, profile: fullProfile });
    });

    // ═══════════════════════════════════════════════════════════════════════════
    // POST /profile/tier-sync — Sync tier changes from C2C (localhost-only)
    //
    // Called by C2C when a user purchases Commander tier or similar.
    // Body: { persistentId, tier, premium_effects? }
    //   tier: 'free' | 'commander' | 'lifetime' | 'founder'
    //   premium_effects: optional JSON array of unlocked effect IDs
    // ═══════════════════════════════════════════════════════════════════════════
    router.post('/tier-sync', writeLimiter, (req, res) => {
        // Localhost-only — service-to-service call from C2C
        const remoteIp = req.ip || req.connection?.remoteAddress || '';
        const isLocal = remoteIp === '127.0.0.1' || remoteIp === '::1' || remoteIp === '::ffff:127.0.0.1';
        if (!isLocal) {
            return res.status(403).json({ ok: false, error: 'Tier sync is localhost-only' });
        }

        const { persistentId: targetPid, tier, premium_effects } = req.body;
        if (!targetPid || !tier) {
            return res.status(400).json({ ok: false, error: 'persistentId and tier required' });
        }

        const VALID_TIERS = ['free', 'commander', 'lifetime', 'founder'];
        if (!VALID_TIERS.includes(tier)) {
            return res.status(400).json({ ok: false, error: `Invalid tier. Must be one of: ${VALID_TIERS.join(', ')}` });
        }

        // Build update payload
        const update = { persistentId: targetPid, tier };
        if (premium_effects) {
            try {
                const arr = typeof premium_effects === 'string'
                    ? JSON.parse(premium_effects)
                    : premium_effects;
                if (Array.isArray(arr)) {
                    update.premium_effects = JSON.stringify(arr);
                }
            } catch { /* ignore invalid */ }
        }

        // If upgrading to non-free tier, unlock all premium presets by default
        if (tier !== 'free' && !update.premium_effects) {
            const premiumIds = AVATAR_PRESETS.presets
                .filter(p => p.tier === 'premium')
                .map(p => p.id);
            update.premium_effects = JSON.stringify(premiumIds);
        }

        // Upsert the tier change
        const ok = upsertProfile(replication, update, nodeId);
        if (!ok) {
            return res.status(500).json({ ok: false, error: 'Failed to update tier' });
        }

        // Record in replication log
        replication.recordChange('user_profiles', targetPid, 'UPSERT', update);

        // Gossip the tier change across the mesh
        const fullProfile = getProfile(replication, targetPid);
        if (fullProfile) {
            const payload = JSON.stringify(fullProfile);
            const signature = identity.sign(payload);
            gossip.spreadRumor('profile:update', {
                profile: fullProfile,
                signature,
                nodeId,
            });
        }

        log.info('Tier synced and gossiped', { pid: targetPid.slice(0, 12), tier });
        res.json({ ok: true, tier, profile: fullProfile || update });
    });

    return router;
}

/**
 * Wire the profile gossip handler into the mesh rumor listener.
 * Called once during server startup.
 * 
 * When a 'profile:update' rumor arrives, verify the ML-DSA-65 signature
 * and upsert the profile into local replication DB.
 * 
 * @param {Object} params
 * @param {Object} params.mesh - MeshNetwork instance
 * @param {Object} params.replication - ReplicationEngine instance  
 * @param {Object} params.identity - NodeIdentity instance (for verification)
 */
export function wireProfileGossip({ mesh, replication, identity }) {
    mesh.on('rumor', (topic, data, origin) => {
        if (topic !== 'profile:update') return;

        const { profile, signature, nodeId } = data;
        if (!profile || !signature || !nodeId || !profile.persistentId) {
            log.warn('Invalid profile:update rumor — missing fields');
            return;
        }

        // Verify ML-DSA-65 signature
        try {
            const payload = JSON.stringify(profile);
            const valid = identity.verifyFrom(nodeId, payload, signature);
            if (!valid) {
                log.warn('Profile update signature verification failed', { from: nodeId.slice(0, 12) });
                return;
            }
        } catch (e) {
            log.warn('Profile signature verification error', { error: e.message });
            return;
        }

        // Check timestamp — only accept newer profiles
        const existing = getProfile(replication, profile.persistentId);
        if (existing && existing.updated_at >= profile.updated_at) {
            log.debug('Skipping older profile update', { pid: profile.persistentId.slice(0, 12) });
            return;
        }

        // Upsert the received profile
        upsertProfile(replication, profile, nodeId);
        log.info('Profile received via gossip', {
            pid: profile.persistentId.slice(0, 12),
            from: origin?.slice(0, 12),
            name: profile.displayName || '(unnamed)',
        });
    });

    log.info('Profile gossip handler wired');
}
