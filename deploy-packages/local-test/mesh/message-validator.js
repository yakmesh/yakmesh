/**
 * Message Validation Module
 * @module mesh/message-validator.js
 */

export const SIZE_LIMITS = {
  maxMessageSize: 1024 * 1024,
  maxPayloadSizes: { gossip: 64 * 1024, handshake: 8 * 1024, listing: 128 * 1024, data: 512 * 1024 },
  maxDepth: 10,
  maxArrayLength: 1000,
  maxStringLength: 100000,
};

export class MessageValidator {
  constructor(options = {}) {
    this.limits = { ...SIZE_LIMITS, ...options.limits };
    this.stats = { validated: 0, rejected: 0, rejectionReasons: new Map() };
  }

  validateRaw(rawMessage, type = 'gossip') {
    const size = typeof rawMessage === 'string' ? Buffer.byteLength(rawMessage, 'utf8') : rawMessage.length;
    if (size > this.limits.maxMessageSize) return this._reject('Message too large (' + size + ' > ' + this.limits.maxMessageSize + ')');
    const typeLimit = this.limits.maxPayloadSizes[type] || this.limits.maxPayloadSizes.gossip;
    if (size > typeLimit) return this._reject(type + ' message too large (' + size + ' > ' + typeLimit + ')');
    this.stats.validated++;
    return { valid: true, size };
  }

  validateStructure(message, type = 'gossip') {
    if (message === null || message === undefined) return this._reject('Message is null or undefined');
    if (typeof message !== 'object') return this._reject('Expected object, got ' + typeof message);
    const depthCheck = this._checkDepth(message, 0);
    if (!depthCheck.valid) return depthCheck;
    const requiredCheck = this._checkRequiredFields(message, type);
    if (!requiredCheck.valid) return requiredCheck;
    this.stats.validated++;
    return { valid: true };
  }

  _checkDepth(obj, depth) {
    if (depth > this.limits.maxDepth) return this._reject('Message nesting too deep');
    if (Array.isArray(obj)) {
      if (obj.length > this.limits.maxArrayLength) return this._reject('Array too long');
      for (const item of obj) {
        if (typeof item === 'object' && item !== null) {
          const check = this._checkDepth(item, depth + 1);
          if (!check.valid) return check;
        }
      }
    } else if (typeof obj === 'object' && obj !== null) {
      for (const value of Object.values(obj)) {
        if (typeof value === 'string' && value.length > this.limits.maxStringLength) return this._reject('String too long');
        if (typeof value === 'object' && value !== null) {
          const check = this._checkDepth(value, depth + 1);
          if (!check.valid) return check;
        }
      }
    }
    return { valid: true };
  }

  _checkRequiredFields(message, type) {
    const requirements = { handshake: ['type', 'nodeId'], gossip: ['type'], listing: ['type', 'data', 'signature'], data: ['type', 'payload'] };
    const required = requirements[type] || requirements.gossip;
    for (const field of required) { if (!(field in message)) return this._reject('Missing required field: ' + field); }
    return { valid: true };
  }

  _reject(reason) {
    this.stats.rejected++;
    const count = this.stats.rejectionReasons.get(reason) || 0;
    this.stats.rejectionReasons.set(reason, count + 1);
    return { valid: false, reason };
  }

  getStats() {
    return { validated: this.stats.validated, rejected: this.stats.rejected, topReasons: [...this.stats.rejectionReasons.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10) };
  }
}

export class SafeJsonParser {
  constructor(options = {}) {
    this.maxSize = options.maxSize || SIZE_LIMITS.maxMessageSize;
  }

  parse(json) {
    if (typeof json !== 'string') return { success: false, error: 'Input must be a string' };
    if (json.length > this.maxSize) return { success: false, error: 'JSON too large' };
    if (/__proto__|constructor.*prototype/i.test(json)) return { success: false, error: 'Suspicious content detected' };
    try { return { success: true, data: JSON.parse(json) }; }
    catch (e) { return { success: false, error: 'JSON parse error: ' + e.message }; }
  }
}

export default MessageValidator;
