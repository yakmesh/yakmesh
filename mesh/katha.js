/**
 * KATHA - Kommunication And Threading Handler Architecture
 * 
 * Chat layer for Yakmesh providing rich messaging features:
 * - Text messages with formatting
 * - Reactions (emoji responses to messages)
 * - Typing indicators (ephemeral presence)
 * - Reply/threading (message relationships)
 * - Read receipts (optional acknowledgment)
 * - Media embeds (images, GIFs as base64)
 * 
 * Etymology: कथा (katha) = story, talk, narrative in Sanskrit
 * 
 * KATHA works on top of GUMBA bundles or direct ANNEX channels.
 * Messages are signed and optionally encrypted depending on the transport.
 * 
 * @module mesh/katha
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { randomBytes } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

export const KATHA_CONFIG = Object.freeze({
  // Message constraints
  maxMessageLength: 4000,          // Max text length (like Discord)
  maxReactionEmojis: 20,           // Max unique reactions per message
  maxReactionsPerUser: 1,          // One reaction per user per message
  maxMediaSize: 10 * 1024 * 1024,  // 10MB max media
  
  // Typing indicator
  typingTimeout: 5000,             // Typing expires after 5 seconds
  typingThrottle: 3000,            // Don't send more than once per 3s
  
  // Threading
  maxThreadDepth: 1,               // Direct replies only (no nested threads)
  maxThreadReplies: 1000,          // Max replies to a single message
  
  // Read receipts
  receiptBatchInterval: 1000,      // Batch receipts every 1s
  maxReceiptBatch: 50,             // Max messages in one receipt batch
  
  // Message types
  messageTypes: {
    TEXT: 'katha:text',
    REACTION_ADD: 'katha:reaction:add',
    REACTION_REMOVE: 'katha:reaction:remove',
    TYPING_START: 'katha:typing:start',
    TYPING_STOP: 'katha:typing:stop',
    READ_RECEIPT: 'katha:read',
    EDIT: 'katha:edit',
    DELETE: 'katha:delete',
    MEDIA: 'katha:media',
  },
  
  // Media types
  mediaTypes: {
    IMAGE: 'image',
    GIF: 'gif',
    FILE: 'file',
  },
});

// ═══════════════════════════════════════════════════════════════════════════════
// KATHA MESSAGE - Base chat message
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * KathaMessage - A chat message in the KATHA protocol
 * 
 * Immutable once created. Edits create new messages with editOf reference.
 */
export class KathaMessage {
  /**
   * @param {Object} options
   * @param {string} options.id - Unique message ID
   * @param {string} options.channelId - Channel/room this message belongs to
   * @param {string} options.senderId - Sender's node ID
   * @param {string} options.content - Message text content
   * @param {string} [options.replyTo] - ID of message being replied to
   * @param {number} [options.timestamp] - Unix timestamp
   */
  constructor(options = {}) {
    this.id = options.id || KathaMessage.generateId();
    this.type = KATHA_CONFIG.messageTypes.TEXT;
    this.channelId = options.channelId;
    this.senderId = options.senderId;
    this.content = options.content || '';
    this.replyTo = options.replyTo || null;
    this.timestamp = options.timestamp !== undefined ? options.timestamp : Date.now();
    this.editedAt = options.editedAt || null;
    this.reactions = new Map(); // emoji -> Set of userIds
  }

  /**
   * Generate a unique message ID
   */
  static generateId() {
    const timestamp = Date.now().toString(36);
    const random = bytesToHex(randomBytes(8));
    return `${timestamp}-${random}`;
  }

  /**
   * Validate message content
   */
  validate() {
    const errors = [];
    
    if (!this.channelId) {
      errors.push('channelId is required');
    }
    if (!this.senderId) {
      errors.push('senderId is required');
    }
    if (typeof this.content !== 'string') {
      errors.push('content must be a string');
    }
    if (this.content.length > KATHA_CONFIG.maxMessageLength) {
      errors.push(`content exceeds max length of ${KATHA_CONFIG.maxMessageLength}`);
    }
    
    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Add a reaction
   * @returns {boolean} true if reaction was added
   */
  addReaction(emoji, userId) {
    if (!emoji || !userId) return false;
    
    // Check limits
    if (this.reactions.size >= KATHA_CONFIG.maxReactionEmojis && !this.reactions.has(emoji)) {
      return false;
    }
    
    if (!this.reactions.has(emoji)) {
      this.reactions.set(emoji, new Set());
    }
    
    const users = this.reactions.get(emoji);
    if (users.has(userId)) return false;
    
    users.add(userId);
    return true;
  }

  /**
   * Remove a reaction
   * @returns {boolean} true if reaction was removed
   */
  removeReaction(emoji, userId) {
    if (!this.reactions.has(emoji)) return false;
    
    const users = this.reactions.get(emoji);
    const removed = users.delete(userId);
    
    // Clean up empty reaction sets
    if (users.size === 0) {
      this.reactions.delete(emoji);
    }
    
    return removed;
  }

  /**
   * Get reaction counts
   */
  getReactionCounts() {
    const counts = {};
    for (const [emoji, users] of this.reactions) {
      counts[emoji] = users.size;
    }
    return counts;
  }

  /**
   * Check if user reacted with emoji
   */
  hasUserReaction(emoji, userId) {
    return this.reactions.has(emoji) && this.reactions.get(emoji).has(userId);
  }

  /**
   * Serialize for transmission
   */
  toJSON() {
    // Convert reactions Map to plain object
    const reactions = {};
    for (const [emoji, users] of this.reactions) {
      reactions[emoji] = Array.from(users);
    }
    
    return {
      id: this.id,
      type: this.type,
      channelId: this.channelId,
      senderId: this.senderId,
      content: this.content,
      replyTo: this.replyTo,
      timestamp: this.timestamp,
      editedAt: this.editedAt,
      reactions,
    };
  }

  /**
   * Deserialize from transmission
   */
  static fromJSON(json) {
    const msg = new KathaMessage({
      id: json.id,
      channelId: json.channelId,
      senderId: json.senderId,
      content: json.content,
      replyTo: json.replyTo,
      timestamp: json.timestamp,
      editedAt: json.editedAt,
    });
    msg.type = json.type || KATHA_CONFIG.messageTypes.TEXT;
    
    // Restore reactions
    if (json.reactions) {
      for (const [emoji, users] of Object.entries(json.reactions)) {
        msg.reactions.set(emoji, new Set(users));
      }
    }
    
    return msg;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KATHA REACTION - Reaction event
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * KathaReaction - A reaction add/remove event
 */
export class KathaReaction {
  constructor(options = {}) {
    this.type = options.add !== false 
      ? KATHA_CONFIG.messageTypes.REACTION_ADD 
      : KATHA_CONFIG.messageTypes.REACTION_REMOVE;
    this.messageId = options.messageId;
    this.channelId = options.channelId;
    this.userId = options.userId;
    this.emoji = options.emoji;
    this.timestamp = options.timestamp || Date.now();
  }

  validate() {
    const errors = [];
    if (!this.messageId) errors.push('messageId is required');
    if (!this.channelId) errors.push('channelId is required');
    if (!this.userId) errors.push('userId is required');
    if (!this.emoji) errors.push('emoji is required');
    // Basic emoji validation (single grapheme cluster or shortcode)
    if (this.emoji && this.emoji.length > 32) errors.push('emoji too long');
    
    return { valid: errors.length === 0, errors };
  }

  toJSON() {
    return {
      type: this.type,
      messageId: this.messageId,
      channelId: this.channelId,
      userId: this.userId,
      emoji: this.emoji,
      timestamp: this.timestamp,
    };
  }

  static fromJSON(json) {
    return new KathaReaction({
      add: json.type === KATHA_CONFIG.messageTypes.REACTION_ADD,
      messageId: json.messageId,
      channelId: json.channelId,
      userId: json.userId,
      emoji: json.emoji,
      timestamp: json.timestamp,
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KATHA TYPING - Typing indicator
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * KathaTyping - Typing indicator event (ephemeral, not stored)
 */
export class KathaTyping {
  constructor(options = {}) {
    this.type = options.stop 
      ? KATHA_CONFIG.messageTypes.TYPING_STOP 
      : KATHA_CONFIG.messageTypes.TYPING_START;
    this.channelId = options.channelId;
    this.userId = options.userId;
    this.timestamp = options.timestamp || Date.now();
  }

  /**
   * Check if this typing indicator has expired
   */
  isExpired() {
    return Date.now() - this.timestamp > KATHA_CONFIG.typingTimeout;
  }

  toJSON() {
    return {
      type: this.type,
      channelId: this.channelId,
      userId: this.userId,
      timestamp: this.timestamp,
    };
  }

  static fromJSON(json) {
    return new KathaTyping({
      stop: json.type === KATHA_CONFIG.messageTypes.TYPING_STOP,
      channelId: json.channelId,
      userId: json.userId,
      timestamp: json.timestamp,
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KATHA READ RECEIPT - Read acknowledgment
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * KathaReadReceipt - Batch read receipt
 */
export class KathaReadReceipt {
  constructor(options = {}) {
    this.type = KATHA_CONFIG.messageTypes.READ_RECEIPT;
    this.channelId = options.channelId;
    this.userId = options.userId;
    this.messageIds = options.messageIds || [];
    this.lastReadId = options.lastReadId || null; // Alternative: just track last read
    this.timestamp = options.timestamp || Date.now();
  }

  /**
   * Add a message ID to the receipt batch
   */
  addMessage(messageId) {
    if (this.messageIds.length >= KATHA_CONFIG.maxReceiptBatch) {
      return false;
    }
    if (!this.messageIds.includes(messageId)) {
      this.messageIds.push(messageId);
    }
    return true;
  }

  toJSON() {
    return {
      type: this.type,
      channelId: this.channelId,
      userId: this.userId,
      messageIds: this.messageIds,
      lastReadId: this.lastReadId,
      timestamp: this.timestamp,
    };
  }

  static fromJSON(json) {
    return new KathaReadReceipt({
      channelId: json.channelId,
      userId: json.userId,
      messageIds: json.messageIds,
      lastReadId: json.lastReadId,
      timestamp: json.timestamp,
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KATHA MEDIA - Image/GIF/File embed
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * KathaMedia - Media attachment
 */
export class KathaMedia {
  constructor(options = {}) {
    this.id = options.id || KathaMessage.generateId();
    this.type = KATHA_CONFIG.messageTypes.MEDIA;
    this.mediaType = options.mediaType || KATHA_CONFIG.mediaTypes.IMAGE;
    this.channelId = options.channelId;
    this.senderId = options.senderId;
    this.filename = options.filename || null;
    this.mimeType = options.mimeType || 'application/octet-stream';
    this.size = options.size || 0;
    this.data = options.data || null; // Base64 encoded
    this.hash = options.hash || null; // SHA3-256 of raw data for integrity
    this.caption = options.caption || null;
    this.replyTo = options.replyTo || null;
    this.timestamp = options.timestamp || Date.now();
  }

  /**
   * Create from a buffer
   */
  static fromBuffer(buffer, options = {}) {
    const base64 = buffer.toString('base64');
    const hash = bytesToHex(sha3_256(buffer));
    
    return new KathaMedia({
      ...options,
      data: base64,
      size: buffer.length,
      hash,
    });
  }

  /**
   * Get the raw buffer
   */
  toBuffer() {
    if (!this.data) return null;
    return Buffer.from(this.data, 'base64');
  }

  /**
   * Verify data integrity
   */
  verify() {
    if (!this.data || !this.hash) return false;
    const buffer = this.toBuffer();
    const computed = bytesToHex(sha3_256(buffer));
    return computed === this.hash;
  }

  validate() {
    const errors = [];
    if (!this.channelId) errors.push('channelId is required');
    if (!this.senderId) errors.push('senderId is required');
    if (!this.data) errors.push('data is required');
    if (this.size > KATHA_CONFIG.maxMediaSize) {
      errors.push(`size exceeds max of ${KATHA_CONFIG.maxMediaSize} bytes`);
    }
    if (!Object.values(KATHA_CONFIG.mediaTypes).includes(this.mediaType)) {
      errors.push('invalid mediaType');
    }
    
    return { valid: errors.length === 0, errors };
  }

  toJSON() {
    return {
      id: this.id,
      type: this.type,
      mediaType: this.mediaType,
      channelId: this.channelId,
      senderId: this.senderId,
      filename: this.filename,
      mimeType: this.mimeType,
      size: this.size,
      data: this.data,
      hash: this.hash,
      caption: this.caption,
      replyTo: this.replyTo,
      timestamp: this.timestamp,
    };
  }

  static fromJSON(json) {
    return new KathaMedia({
      id: json.id,
      mediaType: json.mediaType,
      channelId: json.channelId,
      senderId: json.senderId,
      filename: json.filename,
      mimeType: json.mimeType,
      size: json.size,
      data: json.data,
      hash: json.hash,
      caption: json.caption,
      replyTo: json.replyTo,
      timestamp: json.timestamp,
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KATHA EDIT - Message edit
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * KathaEdit - Message edit event
 */
export class KathaEdit {
  constructor(options = {}) {
    this.type = KATHA_CONFIG.messageTypes.EDIT;
    this.messageId = options.messageId;
    this.channelId = options.channelId;
    this.userId = options.userId;
    this.newContent = options.newContent;
    this.timestamp = options.timestamp || Date.now();
  }

  validate() {
    const errors = [];
    if (!this.messageId) errors.push('messageId is required');
    if (!this.channelId) errors.push('channelId is required');
    if (!this.userId) errors.push('userId is required');
    if (typeof this.newContent !== 'string') errors.push('newContent must be a string');
    if (this.newContent && this.newContent.length > KATHA_CONFIG.maxMessageLength) {
      errors.push(`newContent exceeds max length of ${KATHA_CONFIG.maxMessageLength}`);
    }
    
    return { valid: errors.length === 0, errors };
  }

  toJSON() {
    return {
      type: this.type,
      messageId: this.messageId,
      channelId: this.channelId,
      userId: this.userId,
      newContent: this.newContent,
      timestamp: this.timestamp,
    };
  }

  static fromJSON(json) {
    return new KathaEdit({
      messageId: json.messageId,
      channelId: json.channelId,
      userId: json.userId,
      newContent: json.newContent,
      timestamp: json.timestamp,
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KATHA DELETE - Message deletion
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * KathaDelete - Message deletion event
 */
export class KathaDelete {
  constructor(options = {}) {
    this.type = KATHA_CONFIG.messageTypes.DELETE;
    this.messageId = options.messageId;
    this.channelId = options.channelId;
    this.userId = options.userId;
    this.timestamp = options.timestamp || Date.now();
  }

  validate() {
    const errors = [];
    if (!this.messageId) errors.push('messageId is required');
    if (!this.channelId) errors.push('channelId is required');
    if (!this.userId) errors.push('userId is required');
    
    return { valid: errors.length === 0, errors };
  }

  toJSON() {
    return {
      type: this.type,
      messageId: this.messageId,
      channelId: this.channelId,
      userId: this.userId,
      timestamp: this.timestamp,
    };
  }

  static fromJSON(json) {
    return new KathaDelete({
      messageId: json.messageId,
      channelId: json.channelId,
      userId: json.userId,
      timestamp: json.timestamp,
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KATHA CHANNEL - Channel/room state manager
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * KathaChannel - Manages chat state for a channel
 */
export class KathaChannel {
  constructor(channelId) {
    this.channelId = channelId;
    this.messages = new Map(); // id -> KathaMessage
    this.threads = new Map();  // parentId -> Set of replyIds
    this.typing = new Map();   // userId -> timestamp
    this.readReceipts = new Map(); // userId -> lastReadId
    this._typingCleanupInterval = null;
  }

  /**
   * Start typing indicator cleanup
   */
  startTypingCleanup() {
    if (this._typingCleanupInterval) return;
    
    this._typingCleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [userId, timestamp] of this.typing) {
        if (now - timestamp > KATHA_CONFIG.typingTimeout) {
          this.typing.delete(userId);
        }
      }
    }, 1000);
  }

  /**
   * Stop cleanup interval
   */
  stopTypingCleanup() {
    if (this._typingCleanupInterval) {
      clearInterval(this._typingCleanupInterval);
      this._typingCleanupInterval = null;
    }
  }

  /**
   * Add a message
   */
  addMessage(message) {
    if (!(message instanceof KathaMessage)) {
      message = KathaMessage.fromJSON(message);
    }
    
    this.messages.set(message.id, message);
    
    // Track threading
    if (message.replyTo) {
      if (!this.threads.has(message.replyTo)) {
        this.threads.set(message.replyTo, new Set());
      }
      this.threads.get(message.replyTo).add(message.id);
    }
    
    return message;
  }

  /**
   * Get a message
   */
  getMessage(messageId) {
    return this.messages.get(messageId) || null;
  }

  /**
   * Get thread replies
   */
  getThreadReplies(messageId) {
    const replyIds = this.threads.get(messageId);
    if (!replyIds) return [];
    
    return Array.from(replyIds)
      .map(id => this.messages.get(id))
      .filter(Boolean)
      .sort((a, b) => a.timestamp - b.timestamp);
  }

  /**
   * Apply a reaction event
   */
  applyReaction(reaction) {
    const message = this.messages.get(reaction.messageId);
    if (!message) return false;
    
    if (reaction.type === KATHA_CONFIG.messageTypes.REACTION_ADD) {
      return message.addReaction(reaction.emoji, reaction.userId);
    } else {
      return message.removeReaction(reaction.emoji, reaction.userId);
    }
  }

  /**
   * Set typing indicator
   */
  setTyping(userId, isTyping = true) {
    if (isTyping) {
      this.typing.set(userId, Date.now());
    } else {
      this.typing.delete(userId);
    }
  }

  /**
   * Get users currently typing
   */
  getTypingUsers() {
    const now = Date.now();
    const users = [];
    
    for (const [userId, timestamp] of this.typing) {
      if (now - timestamp <= KATHA_CONFIG.typingTimeout) {
        users.push(userId);
      }
    }
    
    return users;
  }

  /**
   * Apply read receipt
   */
  applyReadReceipt(receipt) {
    this.readReceipts.set(receipt.userId, receipt.lastReadId || receipt.messageIds[receipt.messageIds.length - 1]);
  }

  /**
   * Get read status for a message
   */
  getReadBy(messageId) {
    const readers = [];
    
    for (const [userId, lastReadId] of this.readReceipts) {
      const lastRead = this.messages.get(lastReadId);
      const target = this.messages.get(messageId);
      
      if (lastRead && target && lastRead.timestamp >= target.timestamp) {
        readers.push(userId);
      }
    }
    
    return readers;
  }

  /**
   * Edit a message
   */
  editMessage(edit) {
    const message = this.messages.get(edit.messageId);
    if (!message) return null;
    
    // Only sender can edit
    if (message.senderId !== edit.userId) return null;
    
    message.content = edit.newContent;
    message.editedAt = edit.timestamp;
    
    return message;
  }

  /**
   * Delete a message
   */
  deleteMessage(deletion) {
    const message = this.messages.get(deletion.messageId);
    if (!message) return false;
    
    // Only sender can delete
    if (message.senderId !== deletion.userId) return false;
    
    // Remove from threads
    if (message.replyTo) {
      const thread = this.threads.get(message.replyTo);
      if (thread) thread.delete(message.id);
    }
    
    // Don't delete parent if it has replies - just mark content as deleted
    if (this.threads.has(message.id) && this.threads.get(message.id).size > 0) {
      message.content = '[deleted]';
      message.editedAt = deletion.timestamp;
      return true;
    }
    
    this.messages.delete(deletion.messageId);
    return true;
  }

  /**
   * Get messages in time order
   */
  getMessages(options = {}) {
    const { limit = 50, before, after, threadOnly } = options;
    
    let msgs = Array.from(this.messages.values());
    
    // Filter by thread
    if (threadOnly !== undefined) {
      if (threadOnly) {
        msgs = msgs.filter(m => m.replyTo !== null);
      } else {
        msgs = msgs.filter(m => m.replyTo === null);
      }
    }
    
    // Filter by time
    if (before) {
      msgs = msgs.filter(m => m.timestamp < before);
    }
    if (after) {
      msgs = msgs.filter(m => m.timestamp > after);
    }
    
    // Sort by timestamp
    msgs.sort((a, b) => a.timestamp - b.timestamp);
    
    // Apply limit
    if (limit) {
      msgs = msgs.slice(-limit);
    }
    
    return msgs;
  }

  /**
   * Get channel stats
   */
  getStats() {
    return {
      channelId: this.channelId,
      messageCount: this.messages.size,
      threadCount: this.threads.size,
      typingUsers: this.getTypingUsers().length,
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KATHA HUB - Multi-channel manager
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * KathaHub - Manages multiple chat channels
 */
export class KathaHub {
  constructor() {
    this.channels = new Map();
    this.eventHandlers = new Map();
  }

  /**
   * Get or create a channel
   */
  getChannel(channelId) {
    if (!this.channels.has(channelId)) {
      const channel = new KathaChannel(channelId);
      channel.startTypingCleanup();
      this.channels.set(channelId, channel);
    }
    return this.channels.get(channelId);
  }

  /**
   * Remove a channel
   */
  removeChannel(channelId) {
    const channel = this.channels.get(channelId);
    if (channel) {
      channel.stopTypingCleanup();
      this.channels.delete(channelId);
    }
  }

  /**
   * Handle incoming KATHA event
   */
  handleEvent(event) {
    const channelId = event.channelId;
    if (!channelId) return null;
    
    const channel = this.getChannel(channelId);
    let result = null;
    
    switch (event.type) {
      case KATHA_CONFIG.messageTypes.TEXT:
        result = channel.addMessage(KathaMessage.fromJSON(event));
        break;
        
      case KATHA_CONFIG.messageTypes.MEDIA:
        result = channel.addMessage(KathaMedia.fromJSON(event));
        break;
        
      case KATHA_CONFIG.messageTypes.REACTION_ADD:
      case KATHA_CONFIG.messageTypes.REACTION_REMOVE:
        result = channel.applyReaction(KathaReaction.fromJSON(event));
        break;
        
      case KATHA_CONFIG.messageTypes.TYPING_START:
        channel.setTyping(event.userId, true);
        result = true;
        break;
        
      case KATHA_CONFIG.messageTypes.TYPING_STOP:
        channel.setTyping(event.userId, false);
        result = true;
        break;
        
      case KATHA_CONFIG.messageTypes.READ_RECEIPT:
        channel.applyReadReceipt(KathaReadReceipt.fromJSON(event));
        result = true;
        break;
        
      case KATHA_CONFIG.messageTypes.EDIT:
        result = channel.editMessage(KathaEdit.fromJSON(event));
        break;
        
      case KATHA_CONFIG.messageTypes.DELETE:
        result = channel.deleteMessage(KathaDelete.fromJSON(event));
        break;
    }
    
    // Emit event
    this._emit(event.type, event, result);
    
    return result;
  }

  /**
   * Register event handler
   */
  on(eventType, handler) {
    if (!this.eventHandlers.has(eventType)) {
      this.eventHandlers.set(eventType, []);
    }
    this.eventHandlers.get(eventType).push(handler);
  }

  /**
   * Remove event handler
   */
  off(eventType, handler) {
    const handlers = this.eventHandlers.get(eventType);
    if (handlers) {
      const idx = handlers.indexOf(handler);
      if (idx >= 0) handlers.splice(idx, 1);
    }
  }

  /**
   * Emit event to handlers
   */
  _emit(eventType, event, result) {
    const handlers = this.eventHandlers.get(eventType) || [];
    for (const handler of handlers) {
      try {
        handler(event, result);
      } catch (err) {
        console.error('Katha handler error:', err);
      }
    }
  }

  /**
   * Cleanup all channels
   */
  cleanup() {
    for (const channel of this.channels.values()) {
      channel.stopTypingCleanup();
    }
    this.channels.clear();
  }

  /**
   * Get hub stats
   */
  getStats() {
    const stats = {
      channelCount: this.channels.size,
      totalMessages: 0,
      channels: {},
    };
    
    for (const [id, channel] of this.channels) {
      const channelStats = channel.getStats();
      stats.totalMessages += channelStats.messageCount;
      stats.channels[id] = channelStats;
    }
    
    return stats;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export default {
  KATHA_CONFIG,
  KathaMessage,
  KathaReaction,
  KathaTyping,
  KathaReadReceipt,
  KathaMedia,
  KathaEdit,
  KathaDelete,
  KathaChannel,
  KathaHub,
};
