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
 * Yakmesh KARMA-Adaptive Rate Limiting + Input Validation
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * PHILOSOPHY: TRUST ENABLES THROUGHPUT
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Traditional rate limiting: Fixed thresholds (e.g., 100 req/min for everyone).
 * KARMA-adaptive: Throughput scales with earned trust.
 * 
 * - Unknown peers: Strict limits (10 req/min)
 * - Low KARMA (0-30): Cautious (25 req/min)
 * - Medium KARMA (31-60): Standard (50 req/min)
 * - High KARMA (61-85): Elevated (100 req/min)
 * - Excellent KARMA (86-100): Trusted (200 req/min)
 * 
 * This creates economic incentive: good behavior → higher throughput capacity.
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * INTEGRATION WITH SANGHA
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * The rate limiter participates in SANGHA collective attestation:
 * - Reports current load and block counts during circulation
 * - Can trigger collective response to coordinated flood attacks
 * - Receives warnings from other components about suspicious peers
 * 
 * @module security/karma-rate-limiter
 * @version 1.0.0
 */

import { createLogger } from '../utils/logger.js';
import { EventEmitter } from 'events';

// AGUWA — canonical mesh time source
import { aguwa } from '../mesh/aguwa.js';

const log = createLogger('security:karma-rate-limiter');

// =============================================================================
// CONSTANTS
// =============================================================================

/** Rate limit tiers based on KARMA score */
export const KARMA_TIERS = {
  UNKNOWN: { min: -1, max: -1, limit: 10, window: 60000, label: 'Unknown' },
  HOSTILE: { min: 0, max: 10, limit: 2, window: 60000, label: 'Hostile' },
  LOW: { min: 11, max: 30, limit: 25, window: 60000, label: 'Low' },
  MEDIUM: { min: 31, max: 60, limit: 50, window: 60000, label: 'Medium' },
  HIGH: { min: 61, max: 85, limit: 100, window: 60000, label: 'High' },
  EXCELLENT: { min: 86, max: 100, limit: 200, window: 60000, label: 'Excellent' },
};

/** Request size limits by content type */
export const SIZE_LIMITS = {
  json: 256 * 1024,        // 256 KB for JSON payloads
  binary: 16 * 1024 * 1024, // 16 MB for binary content
  websocket: 64 * 1024,    // 64 KB per WebSocket message
  gossip: 4 * 1024,        // 4 KB for gossip messages
};

/** Burst multiplier (allows short bursts above rate limit) */
const BURST_MULTIPLIER = 2;

/** Block duration after exceeding limits (ms) */
const BLOCK_DURATION = 60000;

/** Escalation: each violation increases block duration */
const BLOCK_ESCALATION = 2;

// =============================================================================
// RATE BUCKET
// =============================================================================

/**
 * RateBucket — Token bucket for a single peer
 */
class RateBucket {
  peerId;
  karma;
  tier;
  tokens;
  lastRefill;
  violations;
  blockedUntil;

  constructor(peerId, karma = -1) {
    this.peerId = peerId;
    this.karma = karma;
    this.tier = this.#getTier(karma);
    this.tokens = this.tier.limit * BURST_MULTIPLIER;
    this.lastRefill = aguwa.now();
    this.violations = 0;
    this.blockedUntil = 0;

    Object.seal(this);
  }

  #getTier(karma) {
    if (karma < 0) return KARMA_TIERS.UNKNOWN;
    if (karma <= 10) return KARMA_TIERS.HOSTILE;
    if (karma <= 30) return KARMA_TIERS.LOW;
    if (karma <= 60) return KARMA_TIERS.MEDIUM;
    if (karma <= 85) return KARMA_TIERS.HIGH;
    return KARMA_TIERS.EXCELLENT;
  }

  /**
   * Update KARMA score (may change tier)
   */
  updateKarma(newKarma) {
    const oldTier = this.tier;
    this.karma = newKarma;
    this.tier = this.#getTier(newKarma);

    if (oldTier !== this.tier) {
      log.debug('Peer tier changed', {
        peerId: this.peerId.slice(0, 16),
        oldTier: oldTier.label,
        newTier: this.tier.label,
        newLimit: this.tier.limit,
      });
    }
  }

  /**
   * Refill tokens based on elapsed time
   */
  #refill() {
    const now = aguwa.now();
    const elapsed = Math.max(0, now - this.lastRefill);
    const tokensPerMs = this.tier.limit / this.tier.window;
    const newTokens = Math.floor(elapsed * tokensPerMs);

    if (newTokens > 0) {
      this.tokens = Math.min(
        this.tokens + newTokens,
        this.tier.limit * BURST_MULTIPLIER
      );
      this.lastRefill = now;
    }
  }

  /**
   * Try to consume tokens
   * @param {number} cost - Tokens to consume (default 1)
   * @returns {{ allowed: boolean, remaining: number, reason?: string }}
   */
  consume(cost = 1) {
    const now = aguwa.now();

    // Check if blocked
    if (this.blockedUntil > now) {
      return {
        allowed: false,
        remaining: 0,
        reason: `Blocked for ${Math.ceil((this.blockedUntil - now) / 1000)}s`,
        retryAfter: this.blockedUntil - now,
      };
    }

    // Refill tokens
    this.#refill();

    // Check if enough tokens
    if (this.tokens < cost) {
      this.violations++;
      const blockDuration = BLOCK_DURATION * Math.pow(BLOCK_ESCALATION, Math.min(this.violations - 1, 5));
      this.blockedUntil = now + blockDuration;

      log.warn('Rate limit exceeded — peer blocked', {
        peerId: this.peerId.slice(0, 16),
        tier: this.tier.label,
        violations: this.violations,
        blockDuration: Math.round(blockDuration / 1000) + 's',
      });

      return {
        allowed: false,
        remaining: 0,
        reason: `Rate limit exceeded (${this.tier.label} tier: ${this.tier.limit}/min)`,
        retryAfter: blockDuration,
      };
    }

    this.tokens -= cost;
    return {
      allowed: true,
      remaining: this.tokens,
    };
  }

  /**
   * Get current status
   */
  getStatus() {
    this.#refill();
    return {
      peerId: this.peerId,
      karma: this.karma,
      tier: this.tier.label,
      limit: this.tier.limit,
      remaining: Math.floor(this.tokens),
      violations: this.violations,
      blocked: this.blockedUntil > aguwa.now(),
    };
  }
}

// =============================================================================
// INPUT VALIDATOR
// =============================================================================

/**
 * InputValidator — Validates and sanitizes incoming data
 */
export class InputValidator {
  #schemas;

  constructor() {
    this.#schemas = new Map();
    this.#registerBuiltinSchemas();
  }

  /**
   * Register built-in validation schemas
   */
  #registerBuiltinSchemas() {
    // Node ID schema
    this.#schemas.set('nodeId', {
      type: 'string',
      pattern: /^node-[a-z0-9-]+-pq-[A-Za-z0-9]{4}$/,
      minLength: 20,
      maxLength: 100,
    });

    // Public key (hex)
    this.#schemas.set('publicKey', {
      type: 'string',
      pattern: /^[a-f0-9]+$/i,
      minLength: 64,
      maxLength: 4096,
    });

    // Signature (hex)
    this.#schemas.set('signature', {
      type: 'string',
      pattern: /^[a-f0-9]+$/i,
      minLength: 128,
      maxLength: 8192,
    });

    // Hash (SHA3-256 hex)
    this.#schemas.set('hash', {
      type: 'string',
      pattern: /^[a-f0-9]{64}$/i,
    });

    // Timestamp (Unix ms)
    this.#schemas.set('timestamp', {
      type: 'number',
      min: 0,
      max: aguwa.now() + 86400000, // Max 1 day in future
    });

    // Gossip message
    this.#schemas.set('gossipMessage', {
      type: 'object',
      required: ['type', 'from', 'timestamp'],
      properties: {
        type: { type: 'string', maxLength: 50 },
        from: { $ref: 'nodeId' },
        timestamp: { $ref: 'timestamp' },
        payload: { type: 'object', maxSize: SIZE_LIMITS.gossip },
      },
    });

    // DOKO document
    this.#schemas.set('dokoDocument', {
      type: 'object',
      required: ['version', 'type', 'nodeId', 'publicKey', 'signature'],
      properties: {
        version: { type: 'number', min: 1, max: 10 },
        type: { type: 'string', enum: ['node', 'entity', 'content', 'code', 'system'] },
        nodeId: { $ref: 'nodeId' },
        publicKey: { $ref: 'publicKey' },
        signature: { $ref: 'signature' },
      },
    });
  }

  /**
   * Register a custom schema
   */
  registerSchema(name, schema) {
    this.#schemas.set(name, schema);
  }

  /**
   * Validate data against a schema
   * @param {any} data - Data to validate
   * @param {string|object} schemaOrName - Schema name or schema object
   * @returns {{ valid: boolean, errors: string[] }}
   */
  validate(data, schemaOrName) {
    const schema = typeof schemaOrName === 'string'
      ? this.#schemas.get(schemaOrName)
      : schemaOrName;

    if (!schema) {
      return { valid: false, errors: [`Unknown schema: ${schemaOrName}`] };
    }

    const errors = [];
    this.#validateValue(data, schema, '', errors);

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  #validateValue(value, schema, path, errors) {
    // Handle schema references
    if (schema.$ref) {
      const refSchema = this.#schemas.get(schema.$ref);
      if (!refSchema) {
        errors.push(`${path}: Unknown schema reference: ${schema.$ref}`);
        return;
      }
      this.#validateValue(value, refSchema, path, errors);
      return;
    }

    // Type checking
    if (schema.type) {
      const actualType = Array.isArray(value) ? 'array' : typeof value;
      if (actualType !== schema.type) {
        errors.push(`${path}: Expected ${schema.type}, got ${actualType}`);
        return;
      }
    }

    // String validations
    if (schema.type === 'string' && typeof value === 'string') {
      if (schema.minLength && value.length < schema.minLength) {
        errors.push(`${path}: String too short (min: ${schema.minLength})`);
      }
      if (schema.maxLength && value.length > schema.maxLength) {
        errors.push(`${path}: String too long (max: ${schema.maxLength})`);
      }
      if (schema.pattern && !schema.pattern.test(value)) {
        errors.push(`${path}: String doesn't match pattern`);
      }
      if (schema.enum && !schema.enum.includes(value)) {
        errors.push(`${path}: Value not in allowed list: ${schema.enum.join(', ')}`);
      }
    }

    // Number validations
    if (schema.type === 'number' && typeof value === 'number') {
      if (schema.min !== undefined && value < schema.min) {
        errors.push(`${path}: Number too small (min: ${schema.min})`);
      }
      if (schema.max !== undefined && value > schema.max) {
        errors.push(`${path}: Number too large (max: ${schema.max})`);
      }
    }

    // Object validations
    if (schema.type === 'object' && typeof value === 'object' && value !== null) {
      // Check required properties
      if (schema.required) {
        for (const prop of schema.required) {
          if (!(prop in value)) {
            errors.push(`${path}: Missing required property: ${prop}`);
          }
        }
      }

      // Validate properties
      if (schema.properties) {
        for (const [prop, propSchema] of Object.entries(schema.properties)) {
          if (prop in value) {
            this.#validateValue(value[prop], propSchema, `${path}.${prop}`, errors);
          }
        }
      }

      // Check max size
      if (schema.maxSize) {
        const size = JSON.stringify(value).length;
        if (size > schema.maxSize) {
          errors.push(`${path}: Object too large (max: ${schema.maxSize} bytes)`);
        }
      }
    }
  }

  /**
   * Sanitize a string for safe use
   */
  sanitizeString(input, maxLength = 1000) {
    if (typeof input !== 'string') return '';

    // Remove null bytes and control characters
    let sanitized = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

    // Truncate
    if (sanitized.length > maxLength) {
      sanitized = sanitized.slice(0, maxLength);
    }

    return sanitized;
  }

  /**
   * Validate request size
   */
  validateSize(data, type = 'json') {
    const maxSize = SIZE_LIMITS[type] || SIZE_LIMITS.json;
    const size = typeof data === 'string'
      ? data.length
      : JSON.stringify(data).length;

    return {
      valid: size <= maxSize,
      size,
      maxSize,
      error: size > maxSize ? `Payload too large: ${size} > ${maxSize} bytes` : null,
    };
  }
}

// =============================================================================
// KARMA RATE LIMITER
// =============================================================================

/**
 * KarmaRateLimiter — KARMA-adaptive rate limiting with SANGHA integration
 */
export class KarmaRateLimiter extends EventEmitter {
  #buckets;
  #karmaTrust;
  #sangha;
  #validator;
  #stats;

  constructor() {
    super();
    this.#buckets = new Map();
    this.#karmaTrust = null;
    this.#sangha = null;
    this.#validator = new InputValidator();
    this.#stats = {
      allowed: 0,
      blocked: 0,
      validated: 0,
      rejected: 0,
    };

    Object.seal(this);
  }

  /**
   * Bind KARMA trust model for reputation lookups
   */
  bindKarmaTrust(karmaTrust) {
    this.#karmaTrust = karmaTrust;
    log.info('Rate limiter bound to KARMA trust model');
  }

  /**
   * Bind SANGHA for collective response
   */
  bindSangha(sangha) {
    this.#sangha = sangha;
    log.info('Rate limiter bound to SANGHA collective');
  }

  /**
   * Get or create rate bucket for a peer
   */
  #getBucket(peerId) {
    let bucket = this.#buckets.get(peerId);

    if (!bucket) {
      // Get KARMA score if available
      const karma = this.#karmaTrust?.getTrustScore?.(peerId) ?? -1;
      bucket = new RateBucket(peerId, karma);
      this.#buckets.set(peerId, bucket);

      log.debug('Created rate bucket', {
        peerId: peerId.slice(0, 16),
        karma,
        tier: bucket.tier.label,
      });
    }

    return bucket;
  }

  /**
   * Check if request is allowed
   * @param {string} peerId - Peer making the request
   * @param {number} cost - Request cost (default 1)
   * @returns {{ allowed: boolean, remaining: number, tier: string, reason?: string }}
   */
  checkLimit(peerId, cost = 1) {
    const bucket = this.#getBucket(peerId);

    // Update KARMA in case it changed
    if (this.#karmaTrust) {
      const currentKarma = this.#karmaTrust.getTrustScore?.(peerId) ?? -1;
      bucket.updateKarma(currentKarma);
    }

    const result = bucket.consume(cost);

    if (result.allowed) {
      this.#stats.allowed++;
    } else {
      this.#stats.blocked++;

      // Emit event for monitoring
      this.emit('blocked', { peerId, reason: result.reason });

      // Alert SANGHA if many peers are being blocked (possible attack)
      if (this.#stats.blocked % 100 === 0) {
        log.warn('High block rate detected — possible flood attack', {
          blocked: this.#stats.blocked,
          allowed: this.#stats.allowed,
        });
      }
    }

    return {
      allowed: result.allowed,
      remaining: result.remaining,
      tier: bucket.tier.label,
      reason: result.reason,
      retryAfter: result.retryAfter,
    };
  }

  /**
   * Validate and rate-limit a request
   * @param {string} peerId - Peer making the request
   * @param {any} data - Request data
   * @param {string} schemaName - Schema to validate against
   * @param {number} cost - Request cost
   * @returns {{ allowed: boolean, valid: boolean, errors: string[], tier: string }}
   */
  validateAndLimit(peerId, data, schemaName, cost = 1) {
    // First check rate limit
    const limitResult = this.checkLimit(peerId, cost);
    if (!limitResult.allowed) {
      return {
        allowed: false,
        valid: false,
        errors: [limitResult.reason],
        tier: limitResult.tier,
        retryAfter: limitResult.retryAfter,
      };
    }

    // Then validate
    const validation = this.#validator.validate(data, schemaName);

    if (validation.valid) {
      this.#stats.validated++;
    } else {
      this.#stats.rejected++;

      log.debug('Validation failed', {
        peerId: peerId.slice(0, 16),
        schema: schemaName,
        errors: validation.errors.slice(0, 3),
      });
    }

    return {
      allowed: true,
      valid: validation.valid,
      errors: validation.errors,
      tier: limitResult.tier,
      remaining: limitResult.remaining,
    };
  }

  /**
   * Check payload size
   * @param {string} peerId
   * @param {any} data
   * @param {string} type
   * @returns {{ allowed: boolean, valid: boolean, error?: string }}
   */
  checkSize(peerId, data, type = 'json') {
    const limitResult = this.checkLimit(peerId, 0); // Don't consume tokens, just check block
    if (!limitResult.allowed) {
      return { allowed: false, valid: false, error: limitResult.reason };
    }

    const sizeCheck = this.#validator.validateSize(data, type);
    return {
      allowed: true,
      valid: sizeCheck.valid,
      error: sizeCheck.error,
      size: sizeCheck.size,
      maxSize: sizeCheck.maxSize,
    };
  }

  /**
   * Get the input validator
   */
  getValidator() {
    return this.#validator;
  }

  /**
   * Get state for SANGHA attestation
   */
  getState() {
    return {
      component: 'rate-limiter',
      buckets: this.#buckets.size,
      stats: { ...this.#stats },
      tiers: Object.fromEntries(
        Object.entries(KARMA_TIERS).map(([k, v]) => [k, v.limit])
      ),
    };
  }

  /**
   * Get status for API
   */
  getStatus() {
    // Count peers by tier
    const byTier = {};
    for (const tier of Object.values(KARMA_TIERS)) {
      byTier[tier.label] = 0;
    }
    for (const bucket of this.#buckets.values()) {
      byTier[bucket.tier.label]++;
    }

    return {
      trackedPeers: this.#buckets.size,
      byTier,
      stats: { ...this.#stats },
      karmaBound: !!this.#karmaTrust,
      sanghaBound: !!this.#sangha,
    };
  }

  /**
   * Cleanup old buckets (call periodically)
   */
  cleanup(maxAge = 3600000) {
    const now = aguwa.now();
    let removed = 0;

    for (const [peerId, bucket] of this.#buckets) {
      // Remove buckets that haven't been used recently and aren't blocked
      if (bucket.lastRefill < now - maxAge && bucket.blockedUntil < now) {
        this.#buckets.delete(peerId);
        removed++;
      }
    }

    if (removed > 0) {
      log.debug('Cleaned up old rate buckets', { removed, remaining: this.#buckets.size });
    }
  }
}

// =============================================================================
// SINGLETON & EXPORTS
// =============================================================================

let _instance = null;

/**
 * Get the KarmaRateLimiter singleton
 * @returns {KarmaRateLimiter}
 */
export function getKarmaRateLimiter() {
  if (!_instance) {
    _instance = new KarmaRateLimiter();
  }
  return _instance;
}

export default KarmaRateLimiter;
