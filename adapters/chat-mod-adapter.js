/**
 * Yakmesh - Chat Mod Adapter Framework
 * 
 * Secure framework for chat modification plugins that integrate with KATHA.
 * Designed to prevent manipulation and abuse by malicious adapters.
 * 
 * KEY SECURITY PRINCIPLES:
 * 1. Capability Declaration - Adapters MUST declare what they can do
 * 2. Sandboxed Execution - Adapters cannot access raw message content without permission
 * 3. Content Signing - All adapter-generated content is signed and verifiable
 * 4. Rate Limiting - Prevents spam/flooding
 * 5. GUMBA Integration - Respects room role permissions
 * 6. DHARMA Moderation - Behavior-based content filtering (v3.0)
 * 
 * @module adapters/chat-mod-adapter
 * @version 1.1.0
 */

import { EventEmitter } from 'events';
import { createHash } from 'crypto';
import { DharmaModerator, MODERATION_ACTIONS } from '../security/dharma-moderation.js';

/**
 * Chat modification capabilities
 * Adapters MUST declare their capabilities upfront
 */
export const CHAT_MOD_CAPABILITIES = {
  // Message handling
  MSG_READ: 'msg:read',            // Can read message content (requires consent)
  MSG_RESPOND: 'msg:respond',      // Can send responses to messages
  MSG_EMBED: 'msg:embed',          // Can embed rich content in messages
  MSG_REACT: 'msg:react',          // Can add reactions
  
  // Command handling
  CMD_SLASH: 'cmd:slash',          // Can register slash commands (e.g., /bible)
  CMD_MENTION: 'cmd:mention',      // Can respond to @mentions
  CMD_PREFIX: 'cmd:prefix',        // Can handle custom prefixes
  
  // Content generation
  GEN_QUOTE: 'gen:quote',          // Can generate quotes
  GEN_CARD: 'gen:card',            // Can generate rich cards
  GEN_LINK: 'gen:link',            // Can generate links
  
  // Special permissions (require explicit user opt-in)
  SPECIAL_DM: 'special:dm',        // Can send direct messages
  SPECIAL_THREAD: 'special:thread',// Can create threads
  SPECIAL_PIN: 'special:pin',      // Can pin messages (requires ADMIN)
};

/**
 * Security levels for chat mods
 */
export const SECURITY_LEVELS = {
  SANDBOX: 'sandbox',     // Maximum restrictions, no raw content access
  STANDARD: 'standard',   // Normal restrictions, declared capabilities only
  TRUSTED: 'trusted',     // Reduced restrictions (user explicitly trusts)
};

/**
 * Adapter manifest - security declaration
 */
export class ChatModManifest {
  constructor({
    id,
    name,
    version = '1.0.0',
    author = null,
    description = '',
    capabilities = [],
    commands = [],       // Slash commands this adapter handles
    triggers = [],       // Message patterns that trigger this adapter
    rateLimit = { messages: 10, window: 60000 },  // 10 messages per minute
    securityLevel = SECURITY_LEVELS.SANDBOX,
  } = {}) {
    this.id = id;
    this.name = name;
    this.version = version;
    this.author = author;
    this.description = description;
    this.capabilities = new Set(capabilities);
    this.commands = commands;
    this.triggers = triggers;
    this.rateLimit = rateLimit;
    this.securityLevel = securityLevel;
    
    // Generate manifest hash for verification
    this.hash = this._computeHash();
  }
  
  _computeHash() {
    const data = JSON.stringify({
      id: this.id,
      name: this.name,
      version: this.version,
      capabilities: Array.from(this.capabilities).sort(),
      commands: this.commands,
    });
    return createHash('sha256').update(data).digest('hex').slice(0, 16);
  }
  
  toJSON() {
    return {
      ...this,
      capabilities: Array.from(this.capabilities),
    };
  }
}

/**
 * Abstract base class for chat modification adapters
 */
export class ChatModAdapter extends EventEmitter {
  /**
   * @param {ChatModManifest} manifest - Security manifest
   * @param {Object} config - Adapter configuration
   */
  constructor(manifest, config = {}) {
    super();
    
    if (new.target === ChatModAdapter) {
      throw new Error('ChatModAdapter is abstract and cannot be instantiated directly');
    }
    
    if (!(manifest instanceof ChatModManifest)) {
      throw new Error('ChatModAdapter requires a ChatModManifest');
    }
    
    this.manifest = manifest;
    this.config = config;
    this.katha = config.katha || null;
    this.gumba = config.gumba || null;
    
    // DHARMA content moderation (v3.0)
    // Behavior-based filtering - no identity discrimination
    this.moderator = config.moderator || new DharmaModerator();
    this.enableModeration = config.enableModeration !== false; // Default: enabled
    
    // Rate limiting state
    this._rateLimitWindow = [];
    this._rateLimitMax = manifest.rateLimit.messages;
    this._rateLimitWindowMs = manifest.rateLimit.window;
    
    // Statistics
    this.stats = {
      messagesProcessed: 0,
      commandsHandled: 0,
      responsesGenerated: 0,
      rateLimitHits: 0,
      moderationBlocks: 0,
      errors: [],
    };
    
    // Validate manifest
    this._validateManifest();
  }
  
  /**
   * Initialize the adapter
   * @abstract
   */
  async init() {
    throw new Error('init() must be implemented by subclass');
  }
  
  /**
   * Handle an incoming message
   * Called by KATHA when messages match triggers
   * @param {Object} context - Message context (sanitized based on capabilities)
   * @returns {Promise<Object|null>} Response to send, or null
   */
  async handleMessage(context) {
    // Rate limit check
    if (!this._checkRateLimit()) {
      this.stats.rateLimitHits++;
      this.emit('rate-limited', { adapterId: this.manifest.id });
      return null;
    }
    
    // Security: Strip sensitive data based on capabilities
    const sanitizedContext = this._sanitizeContext(context);
    
    // Call subclass implementation
    const response = await this.onMessage(sanitizedContext);
    
    if (response) {
      this.stats.responsesGenerated++;
      // DHARMA moderation check on output
      const moderated = await this._moderateResponse(response, context);
      if (moderated && moderated.blocked) {
        return moderated; // Return moderation notice
      }
      return this._signResponse(moderated || response);
    }
    
    return null;
  }
  
  /**
   * Handle a slash command
   * @param {string} command - Command name (without /)
   * @param {string[]} args - Command arguments
   * @param {Object} context - Command context
   * @returns {Promise<Object|null>}
   */
  async handleCommand(command, args, context) {
    if (!this.manifest.capabilities.has(CHAT_MOD_CAPABILITIES.CMD_SLASH)) {
      throw new Error('Adapter does not have slash command capability');
    }
    
    if (!this.manifest.commands.includes(command)) {
      return null;  // Not our command
    }
    
    if (!this._checkRateLimit()) {
      this.stats.rateLimitHits++;
      return null;
    }
    
    this.stats.commandsHandled++;
    
    const response = await this.onCommand(command, args, this._sanitizeContext(context));
    
    if (response) {
      // DHARMA moderation check on output
      const moderated = await this._moderateResponse(response, context);
      if (moderated && moderated.blocked) {
        return moderated; // Return moderation notice
      }
      return this._signResponse(moderated || response);
    }
    
    return null;
  }
  
  /**
   * Handle incoming message (implement in subclass)
   * @abstract
   * @param {Object} context - Sanitized message context
   * @returns {Promise<Object|null>}
   */
  async onMessage(context) {
    // Default: no response
    return null;
  }
  
  /**
   * Handle slash command (implement in subclass)
   * @abstract
   * @param {string} command - Command name
   * @param {string[]} args - Arguments
   * @param {Object} context - Context
   * @returns {Promise<Object|null>}
   */
  async onCommand(command, args, context) {
    throw new Error('onCommand() must be implemented for slash command adapters');
  }
  
  /**
   * Rate limit check
   * @private
   */
  _checkRateLimit() {
    const now = Date.now();
    
    // Remove expired entries
    this._rateLimitWindow = this._rateLimitWindow.filter(
      t => now - t < this._rateLimitWindowMs
    );
    
    if (this._rateLimitWindow.length >= this._rateLimitMax) {
      return false;
    }
    
    this._rateLimitWindow.push(now);
    return true;
  }
  
  /**
   * Sanitize context based on declared capabilities
   * @private
   */
  _sanitizeContext(context) {
    const sanitized = {
      roomId: context.roomId,
      senderId: context.senderId,
      senderRole: context.senderRole,
      timestamp: context.timestamp,
    };
    
    // Only include message content if adapter has read permission
    if (this.manifest.capabilities.has(CHAT_MOD_CAPABILITIES.MSG_READ)) {
      sanitized.content = context.content;
      sanitized.messageId = context.messageId;
    }
    
    // Only include thread info if adapter has thread permission
    if (this.manifest.capabilities.has(CHAT_MOD_CAPABILITIES.SPECIAL_THREAD)) {
      sanitized.threadId = context.threadId;
      sanitized.parentId = context.parentId;
    }
    
    return sanitized;
  }
  
  /**
   * Sign a response for verification
   * @private
   */
  _signResponse(response) {
    return {
      ...response,
      _adapter: {
        id: this.manifest.id,
        name: this.manifest.name,
        version: this.manifest.version,
        manifestHash: this.manifest.hash,
        timestamp: Date.now(),
      },
    };
  }
  
  /**
   * Check content against DHARMA moderation rules
   * @private
   * @param {string} content - Content to check
   * @param {Object} context - Context for logging
   * @returns {Promise<Object>} Moderation result
   */
  async _moderateContent(content, context = {}) {
    if (!this.enableModeration || !content) {
      return { allowed: true };
    }
    
    const result = await this.moderator.checkContent(content, {
      adapterId: this.manifest.id,
      ...context,
    });
    
    if (!result.allowed) {
      this.stats.moderationBlocks++;
      this.emit('content-blocked', {
        adapterId: this.manifest.id,
        violationCount: result.violationCount,
        highestSeverity: result.highestSeverity,
        timestamp: Date.now(),
      });
    }
    
    return result;
  }
  
  /**
   * Moderate adapter output before sending
   * @param {Object} response - Response to moderate
   * @param {Object} context - Context
   * @returns {Promise<Object|null>} Moderated response or null if blocked
   */
  async _moderateResponse(response, context = {}) {
    if (!response) return null;
    
    // Extract text content from response
    const textContent = response.content || response.text || 
                       (response.card && response.card.title) ||
                       '';
    
    const result = await this._moderateContent(textContent, context);
    
    if (!result.allowed) {
      return {
        type: 'moderation-notice',
        content: 'Content blocked by community standards',
        blocked: true,
        _adapter: {
          id: this.manifest.id,
          moderated: true,
          timestamp: Date.now(),
        },
      };
    }
    
    return response;
  }
      _verified: true,
    };
  }
  
  /**
   * Validate manifest against known capabilities
   * @private
   */
  _validateManifest() {
    const validCaps = new Set(Object.values(CHAT_MOD_CAPABILITIES));
    
    for (const cap of this.manifest.capabilities) {
      if (!validCaps.has(cap)) {
        console.warn(\[ChatModAdapter] Unknown capability: \\);
      }
    }
    
    // Warn about dangerous combinations
    if (this.manifest.capabilities.has(CHAT_MOD_CAPABILITIES.MSG_READ) &&
        this.manifest.capabilities.has(CHAT_MOD_CAPABILITIES.SPECIAL_DM)) {
      console.warn(\[ChatModAdapter] \ has MSG_READ + SPECIAL_DM - potential privacy concern\);
    }
  }
  
  /**
   * Check if adapter has a capability
   */
  hasCapability(capability) {
    return this.manifest.capabilities.has(capability);
  }
  
  /**
   * Get adapter statistics
   */
  getStats() {
    return {
      ...this.stats,
      manifest: this.manifest.toJSON(),
    };
  }
}

/**
 * Chat Mod Registry - manages installed adapters
 */
export class ChatModRegistry extends EventEmitter {
  constructor() {
    super();
    this.adapters = new Map();  // id -> ChatModAdapter
    this.commandMap = new Map(); // command -> adapter id
    this.triggerPatterns = [];   // { pattern, adapterId }
  }
  
  /**
   * Register an adapter
   * @param {ChatModAdapter} adapter
   */
  register(adapter) {
    if (this.adapters.has(adapter.manifest.id)) {
      throw new Error(\Adapter already registered: \\);
    }
    
    this.adapters.set(adapter.manifest.id, adapter);
    
    // Register commands
    for (const cmd of adapter.manifest.commands) {
      if (this.commandMap.has(cmd)) {
        console.warn(\Command \/\ already registered by \\);
      } else {
        this.commandMap.set(cmd, adapter.manifest.id);
      }
    }
    
    // Register triggers
    for (const trigger of adapter.manifest.triggers) {
      this.triggerPatterns.push({
        pattern: new RegExp(trigger, 'i'),
        adapterId: adapter.manifest.id,
      });
    }
    
    this.emit('adapter-registered', adapter.manifest);
  }
  
  /**
   * Unregister an adapter
   */
  unregister(adapterId) {
    const adapter = this.adapters.get(adapterId);
    if (!adapter) return;
    
    // Remove commands
    for (const cmd of adapter.manifest.commands) {
      if (this.commandMap.get(cmd) === adapterId) {
        this.commandMap.delete(cmd);
      }
    }
    
    // Remove triggers
    this.triggerPatterns = this.triggerPatterns.filter(
      t => t.adapterId !== adapterId
    );
    
    this.adapters.delete(adapterId);
    this.emit('adapter-unregistered', adapterId);
  }
  
  /**
   * Route a slash command to the appropriate adapter
   */
  async routeCommand(command, args, context) {
    const adapterId = this.commandMap.get(command);
    if (!adapterId) return null;
    
    const adapter = this.adapters.get(adapterId);
    if (!adapter) return null;
    
    return adapter.handleCommand(command, args, context);
  }
  
  /**
   * Route a message to matching adapters
   */
  async routeMessage(content, context) {
    const responses = [];
    
    for (const { pattern, adapterId } of this.triggerPatterns) {
      if (pattern.test(content)) {
        const adapter = this.adapters.get(adapterId);
        if (adapter) {
          const response = await adapter.handleMessage({ ...context, content });
          if (response) {
            responses.push(response);
          }
        }
      }
    }
    
    return responses;
  }
  
  /**
   * List all registered adapters
   */
  list() {
    return Array.from(this.adapters.values()).map(a => a.manifest.toJSON());
  }
}

export default ChatModAdapter;
