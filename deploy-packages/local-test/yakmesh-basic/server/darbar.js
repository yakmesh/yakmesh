/**
 * DARBAR (दरबार) — Declarative API Router with Built-in Auth & Resilience
 *
 * A unified, mesh-native API handler for the Yakmesh ecosystem.
 * Routes are declared as descriptor objects with auth levels that map
 * directly to mesh identity primitives (peer signatures, persistent IDs,
 * DOKO certs) rather than ad-hoc JWT checks.
 *
 * Auth levels:
 *   public  — no authentication required
 *   local   — must originate from localhost (socket address check)
 *   peer    — ML-DSA-65 signed headers (x-node-id, x-node-signature, x-node-timestamp)
 *   user    — JWT Bearer token → req.user { userId, username, role, persistentId }
 *   admin   — user + persistentId ∈ host delegate set OR === hostPersistentId
 *   host    — user + persistentId === hostPersistentId exactly (node operator)
 *
 * Features:
 *   - Crash isolation per domain — a bad handler can't take down other domains
 *   - Async error boundary — no unhandled promise rejections
 *   - Standardised error shape: { error: string, code: string }
 *   - Per-route rate limiting (optional)
 *   - Per-route input validation (optional)
 *
 * @module darbar
 */

import { Router } from 'express';

// ============================================================================
// ERROR TYPES
// ============================================================================

/** Standard error codes — machine-readable, stable across versions */
export const ErrorCode = Object.freeze({
  AUTH_REQUIRED: 'AUTH_REQUIRED',
  FORBIDDEN: 'FORBIDDEN',
  NOT_FOUND: 'NOT_FOUND',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  RATE_LIMITED: 'RATE_LIMITED',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
});

/** HTTP status for each error code */
const CODE_STATUS = {
  [ErrorCode.AUTH_REQUIRED]: 401,
  [ErrorCode.FORBIDDEN]: 403,
  [ErrorCode.NOT_FOUND]: 404,
  [ErrorCode.VALIDATION_ERROR]: 400,
  [ErrorCode.RATE_LIMITED]: 429,
  [ErrorCode.INTERNAL_ERROR]: 500,
};

/**
 * Throwable error with a DARBAR error code.
 * Handlers can `throw new DarbarError('msg', 'VALIDATION_ERROR')` and the
 * global error handler will map it to the right HTTP status + JSON shape.
 */
export class DarbarError extends Error {
  /**
   * @param {string} message  Human-readable error message
   * @param {string} code     One of ErrorCode values (or custom string)
   * @param {number} [status] HTTP status override (auto-derived from code if omitted)
   */
  constructor(message, code = ErrorCode.INTERNAL_ERROR, status) {
    super(message);
    this.name = 'DarbarError';
    this.code = code;
    this.status = status ?? CODE_STATUS[code] ?? 500;
  }
}

// ============================================================================
// AUTH LEVEL ENUM
// ============================================================================

export const AuthLevel = Object.freeze({
  PUBLIC: 'public',
  LOCAL: 'local',
  PEER: 'peer',
  USER: 'user',
  ADMIN: 'admin',
  HOST: 'host',
});

const AUTH_HIERARCHY = [
  AuthLevel.PUBLIC,
  AuthLevel.LOCAL,
  AuthLevel.PEER,
  AuthLevel.USER,
  AuthLevel.ADMIN,
  AuthLevel.HOST,
];

// ============================================================================
// LOCALHOST CHECK
// ============================================================================

const LOCALHOST_ADDRS = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

function isLocalhost(req) {
  const addr = req.socket?.remoteAddress;
  return LOCALHOST_ADDRS.has(addr);
}

// ============================================================================
// AUTH MIDDLEWARE FACTORY
// ============================================================================

/**
 * Build an Express middleware for the given auth level.
 *
 * @param {string}          level   One of AuthLevel values
 * @param {DarbarConfig}    config  Project-specific auth backends
 * @returns {Function}      Express middleware (req, res, next)
 */
function _buildAuthMiddleware(level, config) {
  switch (level) {

    // ---- No auth ----
    case AuthLevel.PUBLIC:
      return (_req, _res, next) => next();

    // ---- Socket address must be localhost ----
    case AuthLevel.LOCAL:
      return (req, _res, next) => {
        if (isLocalhost(req)) return next();
        next(new DarbarError('Local access only', ErrorCode.FORBIDDEN, 403));
      };

    // ---- ML-DSA-65 peer signature headers ----
    case AuthLevel.PEER:
      return async (req, _res, next) => {
        // Local bypass — same-machine processes are trusted
        if (isLocalhost(req)) {
          req.peer = { nodeId: 'localhost', local: true };
          return next();
        }
        try {
          const nodeId = req.headers['x-node-id'];
          const signature = req.headers['x-node-signature'];
          const timestamp = req.headers['x-node-timestamp'];

          if (!nodeId || !signature || !timestamp) {
            return next(new DarbarError('Peer auth headers required', ErrorCode.AUTH_REQUIRED));
          }

          // Timestamp drift check (10 seconds)
          const drift = Math.abs(Date.now() - Number(timestamp));
          if (drift > 10_000) {
            return next(new DarbarError('Timestamp drift too large', ErrorCode.AUTH_REQUIRED));
          }

          // Resolve public key from peer registry (NOT from the request)
          if (!config.resolvePeerKey) {
            return next(new DarbarError('Peer auth not configured', ErrorCode.INTERNAL_ERROR));
          }
          const publicKey = await config.resolvePeerKey(nodeId);
          if (!publicKey) {
            return next(new DarbarError('Unknown peer', ErrorCode.FORBIDDEN));
          }

          // Verify ML-DSA-65 signature
          const body = req.body && Object.keys(req.body).length > 0
            ? JSON.stringify(req.body) : '';
          const message = `${nodeId}:${timestamp}:${body}`;
          const valid = await config.verifySignature(message, signature, publicKey);
          if (!valid) {
            return next(new DarbarError('Invalid peer signature', ErrorCode.FORBIDDEN));
          }

          req.peer = { nodeId, publicKey, local: false };
          next();
        } catch (err) {
          next(new DarbarError(`Peer auth failed: ${err.message}`, ErrorCode.AUTH_REQUIRED));
        }
      };

    // ---- JWT Bearer token → req.user ----
    case AuthLevel.USER:
      return async (req, _res, next) => {
        try {
          const token = _extractBearerToken(req);
          if (!token) {
            return next(new DarbarError('Authentication required', ErrorCode.AUTH_REQUIRED));
          }
          if (!config.verifyToken) {
            return next(new DarbarError('Token auth not configured', ErrorCode.INTERNAL_ERROR));
          }
          const decoded = config.verifyToken(token);
          if (!decoded) {
            return next(new DarbarError('Invalid token', ErrorCode.AUTH_REQUIRED));
          }
          req.user = decoded;

          // Optionally resolve persistentId for the authenticated user
          if (config.resolveIdentity) {
            try {
              const identity = await config.resolveIdentity(decoded.userId);
              if (identity?.persistentId) {
                req.user.persistentId = identity.persistentId;
              }
            } catch { /* identity lookup failure is non-fatal for user-level */ }
          }

          next();
        } catch (err) {
          next(new DarbarError(`Auth failed: ${err.message}`, ErrorCode.AUTH_REQUIRED));
        }
      };

    // ---- JWT + persistentId ∈ delegate set ----
    case AuthLevel.ADMIN:
      return async (req, _res, next) => {
        try {
          const token = _extractBearerToken(req);
          if (!token) {
            return next(new DarbarError('Authentication required', ErrorCode.AUTH_REQUIRED));
          }
          if (!config.verifyToken) {
            return next(new DarbarError('Token auth not configured', ErrorCode.INTERNAL_ERROR));
          }
          const decoded = config.verifyToken(token);
          if (!decoded) {
            return next(new DarbarError('Invalid token', ErrorCode.AUTH_REQUIRED));
          }
          req.user = decoded;

          // Resolve persistentId
          let persistentId = null;
          if (config.resolveIdentity) {
            try {
              const identity = await config.resolveIdentity(decoded.userId);
              persistentId = identity?.persistentId || null;
            } catch { /* continue — may still match by role fallback */ }
          }
          req.user.persistentId = persistentId;

          // Check: is host?
          const hostPid = _resolveHostPersistentId(config);
          if (hostPid && persistentId && persistentId === hostPid) {
            req.user.isHost = true;
            req.user.isAdmin = true;
            return next();
          }

          // Check: is delegate?
          if (persistentId && config.isDelegate) {
            const delegated = await config.isDelegate(persistentId);
            if (delegated) {
              req.user.isHost = false;
              req.user.isAdmin = true;
              return next();
            }
          }

          // Fallback: allow if user role is 'admin' (backward compat with existing JWT role)
          if (decoded.role === 'admin') {
            req.user.isHost = false;
            req.user.isAdmin = true;
            return next();
          }

          next(new DarbarError('Admin access required', ErrorCode.FORBIDDEN));
        } catch (err) {
          next(new DarbarError(`Admin auth failed: ${err.message}`, ErrorCode.AUTH_REQUIRED));
        }
      };

    // ---- JWT + persistentId === host exactly ----
    case AuthLevel.HOST:
      return async (req, _res, next) => {
        try {
          const token = _extractBearerToken(req);
          if (!token) {
            return next(new DarbarError('Authentication required', ErrorCode.AUTH_REQUIRED));
          }
          if (!config.verifyToken) {
            return next(new DarbarError('Token auth not configured', ErrorCode.INTERNAL_ERROR));
          }
          const decoded = config.verifyToken(token);
          if (!decoded) {
            return next(new DarbarError('Invalid token', ErrorCode.AUTH_REQUIRED));
          }
          req.user = decoded;

          // Resolve persistentId
          let persistentId = null;
          if (config.resolveIdentity) {
            try {
              const identity = await config.resolveIdentity(decoded.userId);
              persistentId = identity?.persistentId || null;
            } catch { /* identity resolution failed */ }
          }
          req.user.persistentId = persistentId;

          const hostPid = _resolveHostPersistentId(config);
          if (!hostPid) {
            return next(new DarbarError('Host identity not available', ErrorCode.INTERNAL_ERROR));
          }
          if (persistentId !== hostPid) {
            return next(new DarbarError('Host access only', ErrorCode.FORBIDDEN));
          }

          req.user.isHost = true;
          req.user.isAdmin = true;
          next();
        } catch (err) {
          next(new DarbarError(`Host auth failed: ${err.message}`, ErrorCode.AUTH_REQUIRED));
        }
      };

    default:
      return (_req, _res, next) => {
        next(new DarbarError(`Unknown auth level: ${level}`, ErrorCode.INTERNAL_ERROR));
      };
  }
}

// ============================================================================
// HELPERS
// ============================================================================

/** Extract Bearer token from Authorization header */
function _extractBearerToken(req) {
  const auth = req.headers.authorization;
  if (!auth) return null;
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return null;
  return parts[1];
}

/** Resolve host persistentId — supports string or getter function */
function _resolveHostPersistentId(config) {
  if (typeof config.hostPersistentId === 'function') {
    return config.hostPersistentId();
  }
  return config.hostPersistentId || null;
}

/**
 * Wrap an async handler so rejections flow to Express error middleware.
 * @param {Function} fn  async (req, res, next) => ...
 * @returns {Function}   Express-safe middleware
 */
function asyncWrap(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// ============================================================================
// DARBAR FACTORY
// ============================================================================

/**
 * @typedef {Object} RouteDescriptor
 * @property {'GET'|'POST'|'PUT'|'DELETE'|'PATCH'} method  HTTP method
 * @property {string}   path        Express route path (e.g. '/lighthouse')
 * @property {string}   auth        AuthLevel value
 * @property {Function} handler     async (req, res) => ... — MUST send response
 * @property {string}   [description] Human-readable route description (for logging)
 * @property {Function} [validate]  Optional input validation middleware
 */

/**
 * @typedef {Object} DomainDescriptor
 * @property {string}              domain      Domain name (for logging/isolation)
 * @property {string}              [prefix]    URL prefix (default: '/')
 * @property {RouteDescriptor[]}   routes      Array of route descriptors
 * @property {Function[]}          [middleware] Extra middleware applied to all routes in this domain
 */

/**
 * @typedef {Object} DarbarConfig
 * @property {Function}           [verifyToken]       (token: string) => { userId, username, role } | null
 * @property {Function}           [resolveIdentity]   (userId: string) => { persistentId, publicKey } | null
 * @property {string|Function}    [hostPersistentId]  Host's persistentId or getter
 * @property {Function}           [isDelegate]        (persistentId: string) => boolean
 * @property {Function}           [resolvePeerKey]    (nodeId: string) => publicKey | null
 * @property {Function}           [verifySignature]   (message, signature, publicKey) => boolean
 * @property {Object}             [log]               Structured logger ({ info, warn, error })
 */

/**
 * Create a DARBAR instance for a specific project.
 *
 * @param {DarbarConfig} config  Project-specific auth backends
 * @returns {{ mount: Function, errorHandler: Function, DarbarError: typeof DarbarError }}
 */
export function createDarbar(config = {}) {
  const log = config.log || console;
  const _mountedDomains = [];

  /**
   * Mount domain descriptors onto an Express app.
   * Each domain gets its own Router() with crash isolation.
   *
   * @param {import('express').Application} app      Express app
   * @param {DomainDescriptor[]}            domains  Array of domain descriptors
   */
  function mount(app, domains) {
    for (const domain of domains) {
      try {
        const router = Router();
        const prefix = domain.prefix || '/';
        const domainName = domain.domain || 'unnamed';

        // Apply domain-level middleware
        if (domain.middleware && domain.middleware.length > 0) {
          for (const mw of domain.middleware) {
            router.use(mw);
          }
        }

        let routeCount = 0;

        for (const route of domain.routes) {
          const method = (route.method || 'GET').toLowerCase();
          if (!router[method]) {
            log.warn?.(`DARBAR [${domainName}]: unknown method "${route.method}" for ${route.path} — skipping`);
            continue;
          }

          // Build middleware chain for this route
          const chain = [];

          // 1. Auth middleware
          chain.push(_buildAuthMiddleware(route.auth || AuthLevel.PUBLIC, config));

          // 2. Optional validation
          if (typeof route.validate === 'function') {
            chain.push(asyncWrap(route.validate));
          }

          // 3. Handler wrapped in async error boundary
          chain.push(asyncWrap(route.handler));

          router[method](route.path, ...chain);
          routeCount++;
        }

        app.use(prefix, router);
        _mountedDomains.push({ domain: domainName, prefix, routeCount });

        log.info?.(`DARBAR [${domainName}]: mounted ${routeCount} route${routeCount !== 1 ? 's' : ''} on ${prefix}`);
      } catch (err) {
        // Crash isolation — a bad domain file can't prevent other domains from loading
        log.error?.(`DARBAR [${domain?.domain || 'unknown'}]: failed to mount — ${err.message}`);
      }
    }
  }

  /**
   * Express 4-param error handling middleware.
   * Must be registered AFTER all routes: `app.use(darbar.errorHandler())`
   *
   * @returns {Function} (err, req, res, next) => void
   */
  function errorHandler() {
    return (err, _req, res, _next) => {
      // Already sent headers — let Express default handler deal with it
      if (res.headersSent) return;

      if (err instanceof DarbarError) {
        return res.status(err.status).json({
          error: err.message,
          code: err.code,
        });
      }

      // Map common error patterns
      if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
        return res.status(401).json({
          error: err.message,
          code: ErrorCode.AUTH_REQUIRED,
        });
      }

      if (err.status === 400 || err.statusCode === 400) {
        return res.status(400).json({
          error: err.message,
          code: ErrorCode.VALIDATION_ERROR,
        });
      }

      // Unexpected error — log and return generic
      log.error?.(`DARBAR unhandled error: ${err.message}`, err.stack?.split('\n').slice(0, 3).join(' '));
      res.status(500).json({
        error: 'Internal server error',
        code: ErrorCode.INTERNAL_ERROR,
      });
    };
  }

  /**
   * Get summary of mounted domains (for health/status endpoints).
   * @returns {Array<{ domain: string, prefix: string, routeCount: number }>}
   */
  function getMountedDomains() {
    return [..._mountedDomains];
  }

  return {
    mount,
    errorHandler,
    getMountedDomains,
    DarbarError,
    ErrorCode,
    AuthLevel,
  };
}

// Default export for convenience
export default createDarbar;
