/**
 * Self-contained Logger for YakBot
 * No external dependencies - works standalone for deployment
 * 
 * @copyright 2026 YAKMESH™ Contributors
 */

const COLORS = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};

const LEVEL_COLORS = {
  error: COLORS.red,
  warn: COLORS.yellow,
  info: COLORS.cyan,
  debug: COLORS.gray
};

/**
 * Create a logger instance with a namespace
 * @param {string} namespace - Logger namespace (e.g., 'yakbot:main')
 * @returns {Object} Logger with debug, info, warn, error methods
 */
export function createLogger(namespace) {
  const format = (level, ...args) => {
    const timestamp = new Date().toISOString();
    const color = LEVEL_COLORS[level] || COLORS.reset;
    const prefix = `${COLORS.gray}[${timestamp}]${COLORS.reset} ${color}[${level.toUpperCase()}]${COLORS.reset} ${COLORS.magenta}${namespace}${COLORS.reset}`;
    return [prefix, ...args];
  };

  return {
    debug: (...args) => console.log(...format('debug', ...args)),
    info: (...args) => console.log(...format('info', ...args)),
    warn: (...args) => console.warn(...format('warn', ...args)),
    error: (...args) => console.error(...format('error', ...args)),
    log: (...args) => console.log(...format('info', ...args))
  };
}

export default { createLogger };
