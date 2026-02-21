/**
 * KATHA Tests - Chat features test suite
 */

import { describe, it, beforeEach, afterEach } from 'vitest';
import assert from 'node:assert/strict';
import {
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
} from '../katha.js';

// ═══════════════════════════════════════════════════════════════════════════════
// KATHA MESSAGE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('KathaMessage', () => {
  it('should create a message with required fields', () => {
    const msg = new KathaMessage({
      channelId: 'channel-1',
      senderId: 'user-1',
      content: 'Hello, world!',
    });
    
    assert.ok(msg.id);
    assert.equal(msg.channelId, 'channel-1');
    assert.equal(msg.senderId, 'user-1');
    assert.equal(msg.content, 'Hello, world!');
    assert.equal(msg.type, KATHA_CONFIG.messageTypes.TEXT);
    assert.ok(msg.timestamp);
  });

  it('should generate unique IDs', () => {
    const ids = new Set();
    for (let i = 0; i < 100; i++) {
      ids.add(KathaMessage.generateId());
    }
    assert.equal(ids.size, 100);
  });

  it('should validate required fields', () => {
    const msg = new KathaMessage({});
    const result = msg.validate();
    
    assert.equal(result.valid, false);
    assert.ok(result.errors.includes('channelId is required'));
    assert.ok(result.errors.includes('senderId is required'));
  });

  it('should validate content length', () => {
    const msg = new KathaMessage({
      channelId: 'ch-1',
      senderId: 'user-1',
      content: 'x'.repeat(KATHA_CONFIG.maxMessageLength + 1),
    });
    const result = msg.validate();
    
    assert.equal(result.valid, false);
    assert.ok(result.errors.some(e => e.includes('max length')));
  });

  it('should serialize and deserialize', () => {
    const msg = new KathaMessage({
      channelId: 'ch-1',
      senderId: 'user-1',
      content: 'Test message',
      replyTo: 'msg-parent',
    });
    
    const json = msg.toJSON();
    const restored = KathaMessage.fromJSON(json);
    
    assert.equal(restored.id, msg.id);
    assert.equal(restored.content, msg.content);
    assert.equal(restored.replyTo, 'msg-parent');
  });

  it('should support reply threading', () => {
    const parent = new KathaMessage({
      channelId: 'ch-1',
      senderId: 'user-1',
      content: 'Parent message',
    });
    
    const reply = new KathaMessage({
      channelId: 'ch-1',
      senderId: 'user-2',
      content: 'Reply to parent',
      replyTo: parent.id,
    });
    
    assert.equal(reply.replyTo, parent.id);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// REACTION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('KathaReaction', () => {
  it('should add reaction to message', () => {
    const msg = new KathaMessage({
      channelId: 'ch-1',
      senderId: 'user-1',
      content: 'React to this!',
    });
    
    assert.ok(msg.addReaction('👍', 'user-2'));
    assert.ok(msg.addReaction('👍', 'user-3'));
    assert.ok(msg.addReaction('❤️', 'user-2'));
    
    const counts = msg.getReactionCounts();
    assert.equal(counts['👍'], 2);
    assert.equal(counts['❤️'], 1);
  });

  it('should prevent duplicate reactions', () => {
    const msg = new KathaMessage({
      channelId: 'ch-1',
      senderId: 'user-1',
      content: 'React once',
    });
    
    assert.ok(msg.addReaction('👍', 'user-2'));
    assert.equal(msg.addReaction('👍', 'user-2'), false);
    
    assert.equal(msg.getReactionCounts()['👍'], 1);
  });

  it('should remove reactions', () => {
    const msg = new KathaMessage({
      channelId: 'ch-1',
      senderId: 'user-1',
      content: 'Remove reaction',
    });
    
    msg.addReaction('👍', 'user-2');
    assert.ok(msg.removeReaction('👍', 'user-2'));
    
    assert.equal(msg.reactions.size, 0);
  });

  it('should check user reaction', () => {
    const msg = new KathaMessage({
      channelId: 'ch-1',
      senderId: 'user-1',
      content: 'Check reaction',
    });
    
    msg.addReaction('👍', 'user-2');
    
    assert.ok(msg.hasUserReaction('👍', 'user-2'));
    assert.equal(msg.hasUserReaction('👍', 'user-3'), false);
    assert.equal(msg.hasUserReaction('❤️', 'user-2'), false);
  });

  it('should limit reaction emojis per message', () => {
    const msg = new KathaMessage({
      channelId: 'ch-1',
      senderId: 'user-1',
      content: 'Limited reactions',
    });
    
    // Add max reactions
    for (let i = 0; i < KATHA_CONFIG.maxReactionEmojis; i++) {
      msg.addReaction(String.fromCodePoint(0x1F600 + i), 'user-1');
    }
    
    // Try to add one more unique emoji
    const result = msg.addReaction('🎉', 'user-2');
    assert.equal(result, false);
    
    // But can still add to existing emoji
    assert.ok(msg.addReaction(String.fromCodePoint(0x1F600), 'user-2'));
  });

  it('should serialize reactions with message', () => {
    const msg = new KathaMessage({
      channelId: 'ch-1',
      senderId: 'user-1',
      content: 'Serialized reactions',
    });
    
    msg.addReaction('👍', 'user-2');
    msg.addReaction('👍', 'user-3');
    msg.addReaction('❤️', 'user-2');
    
    const json = msg.toJSON();
    const restored = KathaMessage.fromJSON(json);
    
    assert.equal(restored.getReactionCounts()['👍'], 2);
    assert.equal(restored.getReactionCounts()['❤️'], 1);
    assert.ok(restored.hasUserReaction('👍', 'user-2'));
  });

  it('should create reaction events', () => {
    const reaction = new KathaReaction({
      messageId: 'msg-1',
      channelId: 'ch-1',
      userId: 'user-1',
      emoji: '👍',
      add: true,
    });
    
    assert.equal(reaction.type, KATHA_CONFIG.messageTypes.REACTION_ADD);
    assert.ok(reaction.validate().valid);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// TYPING INDICATOR TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('KathaTyping', () => {
  it('should create typing start event', () => {
    const typing = new KathaTyping({
      channelId: 'ch-1',
      userId: 'user-1',
    });
    
    assert.equal(typing.type, KATHA_CONFIG.messageTypes.TYPING_START);
    assert.equal(typing.channelId, 'ch-1');
    assert.equal(typing.userId, 'user-1');
  });

  it('should create typing stop event', () => {
    const typing = new KathaTyping({
      channelId: 'ch-1',
      userId: 'user-1',
      stop: true,
    });
    
    assert.equal(typing.type, KATHA_CONFIG.messageTypes.TYPING_STOP);
  });

  it('should detect expired typing', () => {
    const typing = new KathaTyping({
      channelId: 'ch-1',
      userId: 'user-1',
      timestamp: Date.now() - KATHA_CONFIG.typingTimeout - 1000,
    });
    
    assert.ok(typing.isExpired());
  });

  it('should not be expired when fresh', () => {
    const typing = new KathaTyping({
      channelId: 'ch-1',
      userId: 'user-1',
    });
    
    assert.equal(typing.isExpired(), false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// READ RECEIPT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('KathaReadReceipt', () => {
  it('should create read receipt', () => {
    const receipt = new KathaReadReceipt({
      channelId: 'ch-1',
      userId: 'user-1',
      messageIds: ['msg-1', 'msg-2', 'msg-3'],
    });
    
    assert.equal(receipt.type, KATHA_CONFIG.messageTypes.READ_RECEIPT);
    assert.equal(receipt.messageIds.length, 3);
  });

  it('should add messages to batch', () => {
    const receipt = new KathaReadReceipt({
      channelId: 'ch-1',
      userId: 'user-1',
    });
    
    assert.ok(receipt.addMessage('msg-1'));
    assert.ok(receipt.addMessage('msg-2'));
    
    assert.equal(receipt.messageIds.length, 2);
  });

  it('should not duplicate message IDs', () => {
    const receipt = new KathaReadReceipt({
      channelId: 'ch-1',
      userId: 'user-1',
    });
    
    receipt.addMessage('msg-1');
    receipt.addMessage('msg-1');
    
    assert.equal(receipt.messageIds.length, 1);
  });

  it('should respect batch limit', () => {
    const receipt = new KathaReadReceipt({
      channelId: 'ch-1',
      userId: 'user-1',
    });
    
    for (let i = 0; i < KATHA_CONFIG.maxReceiptBatch; i++) {
      receipt.addMessage(`msg-${i}`);
    }
    
    assert.equal(receipt.addMessage('msg-overflow'), false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// MEDIA TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('KathaMedia', () => {
  it('should create media from buffer', () => {
    const buffer = Buffer.from('Hello, image data!');
    const media = KathaMedia.fromBuffer(buffer, {
      channelId: 'ch-1',
      senderId: 'user-1',
      filename: 'test.txt',
      mimeType: 'text/plain',
    });
    
    assert.ok(media.id);
    assert.equal(media.size, buffer.length);
    assert.ok(media.hash);
    assert.ok(media.data);
  });

  it('should convert back to buffer', () => {
    const original = Buffer.from('Test data 123');
    const media = KathaMedia.fromBuffer(original, {
      channelId: 'ch-1',
      senderId: 'user-1',
    });
    
    const restored = media.toBuffer();
    assert.deepEqual(restored, original);
  });

  it('should verify data integrity', () => {
    const buffer = Buffer.from('Integrity check');
    const media = KathaMedia.fromBuffer(buffer, {
      channelId: 'ch-1',
      senderId: 'user-1',
    });
    
    assert.ok(media.verify());
    
    // Corrupt the data
    media.data = Buffer.from('corrupted').toString('base64');
    assert.equal(media.verify(), false);
  });

  it('should validate size limit', () => {
    const media = new KathaMedia({
      channelId: 'ch-1',
      senderId: 'user-1',
      data: 'base64data',
      size: KATHA_CONFIG.maxMediaSize + 1,
    });
    
    const result = media.validate();
    assert.equal(result.valid, false);
    assert.ok(result.errors.some(e => e.includes('size exceeds')));
  });

  it('should support captions', () => {
    const buffer = Buffer.from('Image with caption');
    const media = KathaMedia.fromBuffer(buffer, {
      channelId: 'ch-1',
      senderId: 'user-1',
      caption: 'Check out this image!',
    });
    
    assert.equal(media.caption, 'Check out this image!');
  });

  it('should serialize and deserialize', () => {
    const buffer = Buffer.from('Serialize me');
    const media = KathaMedia.fromBuffer(buffer, {
      channelId: 'ch-1',
      senderId: 'user-1',
      filename: 'test.bin',
      mediaType: KATHA_CONFIG.mediaTypes.FILE,
    });
    
    const json = media.toJSON();
    const restored = KathaMedia.fromJSON(json);
    
    assert.equal(restored.hash, media.hash);
    assert.equal(restored.filename, 'test.bin');
    assert.ok(restored.verify());
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// EDIT AND DELETE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('KathaEdit', () => {
  it('should create edit event', () => {
    const edit = new KathaEdit({
      messageId: 'msg-1',
      channelId: 'ch-1',
      userId: 'user-1',
      newContent: 'Updated content',
    });
    
    assert.equal(edit.type, KATHA_CONFIG.messageTypes.EDIT);
    assert.ok(edit.validate().valid);
  });

  it('should validate content length', () => {
    const edit = new KathaEdit({
      messageId: 'msg-1',
      channelId: 'ch-1',
      userId: 'user-1',
      newContent: 'x'.repeat(KATHA_CONFIG.maxMessageLength + 1),
    });
    
    const result = edit.validate();
    assert.equal(result.valid, false);
  });
});

describe('KathaDelete', () => {
  it('should create delete event', () => {
    const del = new KathaDelete({
      messageId: 'msg-1',
      channelId: 'ch-1',
      userId: 'user-1',
    });
    
    assert.equal(del.type, KATHA_CONFIG.messageTypes.DELETE);
    assert.ok(del.validate().valid);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// CHANNEL TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('KathaChannel', () => {
  let channel;

  beforeEach(() => {
    channel = new KathaChannel('test-channel');
  });

  afterEach(() => {
    channel.stopTypingCleanup();
  });

  it('should create channel with ID', () => {
    assert.equal(channel.channelId, 'test-channel');
  });

  it('should add and retrieve messages', () => {
    const msg = new KathaMessage({
      channelId: 'test-channel',
      senderId: 'user-1',
      content: 'Hello',
    });
    
    channel.addMessage(msg);
    
    const retrieved = channel.getMessage(msg.id);
    assert.equal(retrieved.content, 'Hello');
  });

  it('should track threading', () => {
    const parent = new KathaMessage({
      channelId: 'test-channel',
      senderId: 'user-1',
      content: 'Parent',
    });
    
    const reply1 = new KathaMessage({
      channelId: 'test-channel',
      senderId: 'user-2',
      content: 'Reply 1',
      replyTo: parent.id,
    });
    
    const reply2 = new KathaMessage({
      channelId: 'test-channel',
      senderId: 'user-3',
      content: 'Reply 2',
      replyTo: parent.id,
    });
    
    channel.addMessage(parent);
    channel.addMessage(reply1);
    channel.addMessage(reply2);
    
    const replies = channel.getThreadReplies(parent.id);
    assert.equal(replies.length, 2);
  });

  it('should apply reactions', () => {
    const msg = new KathaMessage({
      channelId: 'test-channel',
      senderId: 'user-1',
      content: 'React!',
    });
    channel.addMessage(msg);
    
    const reaction = new KathaReaction({
      messageId: msg.id,
      channelId: 'test-channel',
      userId: 'user-2',
      emoji: '👍',
      add: true,
    });
    
    channel.applyReaction(reaction);
    
    const retrieved = channel.getMessage(msg.id);
    assert.equal(retrieved.getReactionCounts()['👍'], 1);
  });

  it('should track typing indicators', () => {
    channel.setTyping('user-1', true);
    channel.setTyping('user-2', true);
    
    const typing = channel.getTypingUsers();
    assert.ok(typing.includes('user-1'));
    assert.ok(typing.includes('user-2'));
    
    channel.setTyping('user-1', false);
    const afterStop = channel.getTypingUsers();
    assert.equal(afterStop.includes('user-1'), false);
    assert.ok(afterStop.includes('user-2'));
  });

  it('should apply read receipts', () => {
    const msg1 = new KathaMessage({
      channelId: 'test-channel',
      senderId: 'user-1',
      content: 'Message 1',
      timestamp: 1000,
    });
    const msg2 = new KathaMessage({
      channelId: 'test-channel',
      senderId: 'user-1',
      content: 'Message 2',
      timestamp: 2000,
    });
    
    channel.addMessage(msg1);
    channel.addMessage(msg2);
    
    const receipt = new KathaReadReceipt({
      channelId: 'test-channel',
      userId: 'user-2',
      lastReadId: msg2.id,
    });
    
    channel.applyReadReceipt(receipt);
    
    const readBy = channel.getReadBy(msg1.id);
    assert.ok(readBy.includes('user-2'));
  });

  it('should edit messages', () => {
    const msg = new KathaMessage({
      channelId: 'test-channel',
      senderId: 'user-1',
      content: 'Original',
    });
    channel.addMessage(msg);
    
    const edit = new KathaEdit({
      messageId: msg.id,
      channelId: 'test-channel',
      userId: 'user-1',
      newContent: 'Edited content',
    });
    
    const edited = channel.editMessage(edit);
    assert.equal(edited.content, 'Edited content');
    assert.ok(edited.editedAt);
  });

  it('should only allow sender to edit', () => {
    const msg = new KathaMessage({
      channelId: 'test-channel',
      senderId: 'user-1',
      content: 'Original',
    });
    channel.addMessage(msg);
    
    const edit = new KathaEdit({
      messageId: msg.id,
      channelId: 'test-channel',
      userId: 'user-2', // Different user
      newContent: 'Hacked!',
    });
    
    const result = channel.editMessage(edit);
    assert.equal(result, null);
  });

  it('should delete messages', () => {
    const msg = new KathaMessage({
      channelId: 'test-channel',
      senderId: 'user-1',
      content: 'Delete me',
    });
    channel.addMessage(msg);
    
    const del = new KathaDelete({
      messageId: msg.id,
      channelId: 'test-channel',
      userId: 'user-1',
    });
    
    assert.ok(channel.deleteMessage(del));
    assert.equal(channel.getMessage(msg.id), null);
  });

  it('should mark parent as deleted if it has replies', () => {
    const parent = new KathaMessage({
      channelId: 'test-channel',
      senderId: 'user-1',
      content: 'Parent with reply',
    });
    const reply = new KathaMessage({
      channelId: 'test-channel',
      senderId: 'user-2',
      content: 'Reply',
      replyTo: parent.id,
    });
    
    channel.addMessage(parent);
    channel.addMessage(reply);
    
    const del = new KathaDelete({
      messageId: parent.id,
      channelId: 'test-channel',
      userId: 'user-1',
    });
    
    channel.deleteMessage(del);
    
    // Parent should still exist but marked as deleted
    const retrieved = channel.getMessage(parent.id);
    assert.equal(retrieved.content, '[deleted]');
  });

  it('should get messages with filters', () => {
    for (let i = 0; i < 5; i++) {
      channel.addMessage(new KathaMessage({
        channelId: 'test-channel',
        senderId: 'user-1',
        content: `Message ${i}`,
        timestamp: i * 1000,
      }));
    }
    
    const all = channel.getMessages();
    assert.equal(all.length, 5);
    
    const limited = channel.getMessages({ limit: 3 });
    assert.equal(limited.length, 3);
    
    const after = channel.getMessages({ after: 2000 });
    assert.equal(after.length, 2);
  });

  it('should provide stats', () => {
    channel.addMessage(new KathaMessage({
      channelId: 'test-channel',
      senderId: 'user-1',
      content: 'Test',
    }));
    channel.setTyping('user-2', true);
    
    const stats = channel.getStats();
    assert.equal(stats.messageCount, 1);
    assert.equal(stats.typingUsers, 1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// HUB TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('KathaHub', () => {
  let hub;

  beforeEach(() => {
    hub = new KathaHub();
  });

  afterEach(() => {
    hub.cleanup();
  });

  it('should create and manage channels', () => {
    const ch1 = hub.getChannel('channel-1');
    const ch2 = hub.getChannel('channel-2');
    
    assert.equal(ch1.channelId, 'channel-1');
    assert.equal(ch2.channelId, 'channel-2');
    
    // Same channel should be returned
    assert.equal(hub.getChannel('channel-1'), ch1);
  });

  it('should handle text message events', () => {
    const msg = {
      id: 'msg-1',
      type: KATHA_CONFIG.messageTypes.TEXT,
      channelId: 'channel-1',
      senderId: 'user-1',
      content: 'Hello hub!',
      timestamp: Date.now(),
    };
    
    const result = hub.handleEvent(msg);
    assert.ok(result);
    
    const channel = hub.getChannel('channel-1');
    assert.equal(channel.getMessage('msg-1').content, 'Hello hub!');
  });

  it('should handle reaction events', () => {
    // First add a message
    hub.handleEvent({
      id: 'msg-1',
      type: KATHA_CONFIG.messageTypes.TEXT,
      channelId: 'channel-1',
      senderId: 'user-1',
      content: 'React to me',
      timestamp: Date.now(),
    });
    
    // Add reaction
    hub.handleEvent({
      type: KATHA_CONFIG.messageTypes.REACTION_ADD,
      messageId: 'msg-1',
      channelId: 'channel-1',
      userId: 'user-2',
      emoji: '👍',
    });
    
    const channel = hub.getChannel('channel-1');
    const msg = channel.getMessage('msg-1');
    assert.equal(msg.getReactionCounts()['👍'], 1);
  });

  it('should handle typing events', () => {
    hub.handleEvent({
      type: KATHA_CONFIG.messageTypes.TYPING_START,
      channelId: 'channel-1',
      userId: 'user-1',
    });
    
    const channel = hub.getChannel('channel-1');
    assert.ok(channel.getTypingUsers().includes('user-1'));
    
    hub.handleEvent({
      type: KATHA_CONFIG.messageTypes.TYPING_STOP,
      channelId: 'channel-1',
      userId: 'user-1',
    });
    
    assert.equal(channel.getTypingUsers().includes('user-1'), false);
  });

  it('should emit events to handlers', () => {
    const received = [];
    
    hub.on(KATHA_CONFIG.messageTypes.TEXT, (event, result) => {
      received.push({ event, result });
    });
    
    hub.handleEvent({
      id: 'msg-1',
      type: KATHA_CONFIG.messageTypes.TEXT,
      channelId: 'channel-1',
      senderId: 'user-1',
      content: 'Event test',
      timestamp: Date.now(),
    });
    
    assert.equal(received.length, 1);
    assert.equal(received[0].event.content, 'Event test');
  });

  it('should remove event handlers', () => {
    let callCount = 0;
    const handler = () => callCount++;
    
    hub.on(KATHA_CONFIG.messageTypes.TEXT, handler);
    
    hub.handleEvent({
      type: KATHA_CONFIG.messageTypes.TEXT,
      channelId: 'ch-1',
      senderId: 'u1',
      content: 'First',
    });
    
    hub.off(KATHA_CONFIG.messageTypes.TEXT, handler);
    
    hub.handleEvent({
      type: KATHA_CONFIG.messageTypes.TEXT,
      channelId: 'ch-1',
      senderId: 'u1',
      content: 'Second',
    });
    
    assert.equal(callCount, 1);
  });

  it('should remove channels', () => {
    hub.getChannel('channel-1');
    assert.equal(hub.channels.size, 1);
    
    hub.removeChannel('channel-1');
    assert.equal(hub.channels.size, 0);
  });

  it('should provide global stats', () => {
    const ch1 = hub.getChannel('channel-1');
    const ch2 = hub.getChannel('channel-2');
    
    ch1.addMessage(new KathaMessage({
      channelId: 'channel-1',
      senderId: 'user-1',
      content: 'Ch1 message',
    }));
    
    ch2.addMessage(new KathaMessage({
      channelId: 'channel-2',
      senderId: 'user-1',
      content: 'Ch2 message 1',
    }));
    ch2.addMessage(new KathaMessage({
      channelId: 'channel-2',
      senderId: 'user-1',
      content: 'Ch2 message 2',
    }));
    
    const stats = hub.getStats();
    assert.equal(stats.channelCount, 2);
    assert.equal(stats.totalMessages, 3);
  });

  it('should cleanup all channels', () => {
    hub.getChannel('ch-1');
    hub.getChannel('ch-2');
    hub.getChannel('ch-3');
    
    hub.cleanup();
    
    assert.equal(hub.channels.size, 0);
  });
});
