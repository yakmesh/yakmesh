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
 * Yakmesh Structured Logger
 * 
 * A configurable logging utility with namespace support, log levels,
 * and optional colored output.
 * 
 * @module utils/logger
 */

// Log level constants
export const LOG_LEVELS = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3,
  TRACE: 4,
};

// Reverse mapping for display
const LEVEL_NAMES = {
  0: 'ERROR',
  1: 'WARN',
  2: 'INFO',
  3: 'DEBUG',
  4: 'TRACE',
};

// Try to load chalk for colored output, fallback to no-op if unavailable
let chalk = null;
try {
  const chalkModule = await import('chalk');
  chalk = chalkModule.default;
} catch {
  // Chalk not available, use fallback
}

// Color functions with graceful fallback
const colors = {
  error: (s) => chalk?.red?.bold?.(s) ?? s,
  warn: (s) => chalk?.yellow?.(s) ?? s,
  info: (s) => chalk?.cyan?.(s) ?? s,
  debug: (s) => chalk?.gray?.(s) ?? s,
  trace: (s) => chalk?.dim?.(s) ?? s,
  timestamp: (s) => chalk?.gray?.(s) ?? s,
  namespace: (s) => chalk?.magenta?.(s) ?? s,
};

// Global log level - can be changed at runtime
let globalLevel = LOG_LEVELS.INFO;

// Parse level from string
function parseLevel(level) {
  if (typeof level === 'number') return level;
  if (typeof level === 'string') {
    const upper = level.toUpperCase();
    if (upper in LOG_LEVELS) return LOG_LEVELS[upper];
  }
  return LOG_LEVELS.INFO;
}

// Initialize from environment
function initFromEnv() {
  const envLevel = process.env.YAKMESH_LOG_LEVEL;
  if (envLevel) {
    globalLevel = parseLevel(envLevel);
  }
}

// Check if we're in test mode (silent)
function isTestMode() {
  return process.env.NODE_ENV === 'test';
}

/**
 * Set the global log level at runtime
 * @param {string|number} level - Log level name or number
 */
export function setGlobalLevel(level) {
  globalLevel = parseLevel(level);
}

/**
 * Get the current global log level
 * @returns {number} Current log level
 */
export function getGlobalLevel() {
  return globalLevel;
}

/**
 * Format a timestamp for log output
 * @returns {string} ISO timestamp
 */
function formatTimestamp() {
  return new Date().toISOString();
}

/**
 * Format data object for log output
 * @param {any} data - Data to format
 * @returns {string} Formatted string
 */
function formatData(data) {
  if (data === undefined || data === null) return '';
  if (typeof data === 'string') return data;
  try {
    return JSON.stringify(data);
  } catch {
    return String(data);
  }
}

/**
 * Create a logger instance with a namespace
 * @param {string} namespace - Logger namespace (e.g., 'mesh:nakpak')
 * @returns {object} Logger instance with error, warn, info, debug, trace methods
 */
export function createLogger(namespace) {
  const log = (level, levelName, colorFn, message, data) => {
    // Silent in test mode
    if (isTestMode()) return;
    
    // Check log level
    if (level > globalLevel) return;
    
    const timestamp = formatTimestamp();
    const formattedData = formatData(data);
    
    const parts = [
      colors.timestamp(`[${timestamp}]`),
      colorFn(`[${levelName}]`),
      colors.namespace(`[${namespace}]`),
      message,
    ];
    
    if (formattedData) {
      parts.push(formattedData);
    }
    
    const output = parts.join(' ');
    
    // Use appropriate console method
    switch (level) {
      case LOG_LEVELS.ERROR:
        console.error(output);
        break;
      case LOG_LEVELS.WARN:
        console.warn(output);
        break;
      default:
        console.log(output);
    }
  };

  return {
    namespace,
    
    error(message, data) {
      log(LOG_LEVELS.ERROR, 'ERROR', colors.error, message, data);
    },
    
    warn(message, data) {
      log(LOG_LEVELS.WARN, 'WARN', colors.warn, message, data);
    },
    
    info(message, data) {
      log(LOG_LEVELS.INFO, 'INFO', colors.info, message, data);
    },
    
    debug(message, data) {
      log(LOG_LEVELS.DEBUG, 'DEBUG', colors.debug, message, data);
    },
    
    trace(message, data) {
      log(LOG_LEVELS.TRACE, 'TRACE', colors.trace, message, data);
    },
    
    /**
     * Create a child logger with extended namespace
     * @param {string} childNamespace - Additional namespace segment
     * @returns {object} Child logger instance
     */
    child(childNamespace) {
      return createLogger(`${namespace}:${childNamespace}`);
    },
    
    /**
     * Check if a log level is enabled
     * @param {string|number} level - Level to check
     * @returns {boolean} True if level is enabled
     */
    isLevelEnabled(level) {
      return parseLevel(level) <= globalLevel;
    },
  };
}

// Initialize from environment on module load
initFromEnv();

// Export level constants for convenience
export const ERROR = LOG_LEVELS.ERROR;
export const WARN = LOG_LEVELS.WARN;
export const INFO = LOG_LEVELS.INFO;
export const DEBUG = LOG_LEVELS.DEBUG;
export const TRACE = LOG_LEVELS.TRACE;

// Default export for convenience
export default { createLogger, setGlobalLevel, getGlobalLevel, LOG_LEVELS };
