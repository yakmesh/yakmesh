/**
 * DHARMA Content Moderation Tests
 * 
 * Tests for behavior-based content moderation.
 * Validates that harmful ACTIONS are blocked, not IDENTITIES.
 * 
 * @module tests/dharma-moderation.test.js
 * @version 3.0.0
 * @license MIT
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';

import {
  DharmaModerator,
  PROHIBITED_CATEGORIES,
  SEVERITY_LEVELS,
  MODERATION_ACTIONS,
  createModerationMiddleware,
  createDefaultModerator,
} from '../security/dharma-moderation.js';

// ============================================================
// DHARMA MODERATOR TESTS
// ============================================================

describe('DharmaModerator', () => {
  let moderator;
  
  beforeEach(() => {
    moderator = new DharmaModerator();
  });
  
  describe('PROHIBITED_CATEGORIES', () => {
    it('should define all required categories', () => {
      assert.ok(PROHIBITED_CATEGORIES.VIOLENCE_INCITEMENT);
      assert.ok(PROHIBITED_CATEGORIES.TERRORISM_PROMOTION);
      assert.ok(PROHIBITED_CATEGORIES.CHILD_EXPLOITATION);
      assert.ok(PROHIBITED_CATEGORIES.HUMAN_TRAFFICKING);
      assert.ok(PROHIBITED_CATEGORIES.WEAPONS_INSTRUCTIONS);
      assert.ok(PROHIBITED_CATEGORIES.HUMAN_SACRIFICE);
    });
    
    it('should have severity levels for all categories', () => {
      for (const [key, category] of Object.entries(PROHIBITED_CATEGORIES)) {
        assert.ok(
          Object.values(SEVERITY_LEVELS).includes(category.severity),
          'Category ' + key + ' should have valid severity'
        );
      }
    });
    
    it('should NOT include religious identities as categories', () => {
      const categoryIds = Object.values(PROHIBITED_CATEGORIES).map(c => c.id);
      
      // These should NEVER be categories (that would be discrimination)
      const forbiddenCategories = [
        'christianity', 'islam', 'judaism', 'hinduism', 'buddhism',
        'wicca', 'paganism', 'atheism', 'agnosticism'
      ];
      
      for (const forbidden of forbiddenCategories) {
        assert.ok(
          !categoryIds.includes(forbidden),
          'Should NOT have category for ' + forbidden
        );
      }
    });
  });
  
  describe('checkContent()', () => {
    it('should allow benign content', async () => {
      const result = await moderator.checkContent('Hello, how are you today?');
      
      assert.strictEqual(result.action, MODERATION_ACTIONS.ALLOW);
      assert.strictEqual(result.allowed, true);
      assert.strictEqual(result.violationCount, 0);
    });
    
    it('should allow religious content without violence', async () => {
      // These should ALL be allowed - we don't discriminate by belief
      const allowedContent = [
        'The Bible teaches love your neighbor',
        'The Quran speaks of peace and mercy',
        'Buddhist meditation brings inner peace',
        'Wiccan rituals celebrate nature',
        'Hindu philosophy includes karma',
        'Jewish tradition values learning',
        'Atheists find meaning through humanism',
      ];
      
      for (const content of allowedContent) {
        const result = await moderator.checkContent(content);
        assert.strictEqual(
          result.allowed, 
          true,
          'Should allow: ' + content
        );
      }
    });
    
    it('should block violence incitement from ANY source', async () => {
      const violentContent = [
        'We must kill them all',
        'Death to our enemies',
        'Exterminate the opposition',
      ];
      
      for (const content of violentContent) {
        const result = await moderator.checkContent(content);
        assert.strictEqual(
          result.allowed, 
          false,
          'Should block: ' + content
        );
        assert.ok(result.violations.some(v => v.categoryId === 'violence-incitement'));
      }
    });
    
    it('should block terrorism promotion', async () => {
      const result = await moderator.checkContent(
        'Join our terrorist cell and attack together'
      );
      
      assert.strictEqual(result.allowed, false);
      assert.ok(result.violations.some(v => v.categoryId === 'terrorism-promotion'));
    });
    
    it('should block child exploitation content', async () => {
      const result = await moderator.checkContent(
        'Looking for child porn material'
      );
      
      assert.strictEqual(result.allowed, false);
      assert.strictEqual(result.highestSeverity, SEVERITY_LEVELS.CRITICAL);
    });
    
    it('should block human sacrifice instructions', async () => {
      const result = await moderator.checkContent(
        'Instructions for human sacrifice ritual'
      );
      
      assert.strictEqual(result.allowed, false);
      assert.ok(result.violations.some(v => v.categoryId === 'human-sacrifice'));
    });
    
    it('should block weapons of mass harm instructions', async () => {
      const result = await moderator.checkContent(
        'Detailed instructions for how to make a bomb'
      );
      
      assert.strictEqual(result.allowed, false);
      assert.ok(result.violations.some(v => v.categoryId === 'weapons-instructions'));
    });
    
    it('should handle obfuscation attempts', async () => {
      // People try to bypass with letter substitutions
      const result = await moderator.checkContent(
        'k1ll th3m @ll'
      );
      
      // After normalization, this should match
      assert.strictEqual(result.allowed, false);
    });
    
    it('should handle null and empty content', async () => {
      const nullResult = await moderator.checkContent(null);
      const emptyResult = await moderator.checkContent('');
      
      assert.strictEqual(nullResult.allowed, true);
      assert.strictEqual(emptyResult.allowed, true);
    });
  });
  
  describe('checkBatch()', () => {
    it('should check multiple content items', async () => {
      const contents = [
        'Hello world',
        'Kill them all',
        'Peace and love',
      ];
      
      const results = await moderator.checkBatch(contents);
      
      assert.strictEqual(results.length, 3);
      assert.strictEqual(results[0].allowed, true);
      assert.strictEqual(results[1].allowed, false);
      assert.strictEqual(results[2].allowed, true);
    });
  });
  
  describe('Custom patterns (host sovereignty)', () => {
    it('should allow adding custom patterns', () => {
      moderator.addCustomPattern({
        id: 'custom-spam',
        severity: SEVERITY_LEVELS.LOW,
        description: 'Custom spam pattern',
        pattern: /\bbuy\s+now\s+limited\s+offer\b/i,
        keywords: [],
        patterns: [],
      });
      
      const config = moderator.getConfiguration();
      assert.strictEqual(config.customPatternCount, 1);
    });
    
    it('should enforce custom patterns', async () => {
      moderator.addCustomPattern({
        id: 'custom-test',
        severity: SEVERITY_LEVELS.HIGH,
        description: 'Test pattern',
        pattern: /\btest-block-phrase\b/i,
        keywords: [],
        patterns: [],
      });
      
      const result = await moderator.checkContent('Please test-block-phrase now');
      
      assert.strictEqual(result.allowed, false);
    });
  });
  
  describe('Event emission', () => {
    it('should emit violation events', async () => {
      let emitted = false;
      
      moderator.on('violation', (event) => {
        emitted = true;
        assert.ok(event.result);
        assert.ok(event.timestamp);
        assert.ok(event.contentHash);
      });
      
      await moderator.checkContent('Kill them all');
      
      assert.strictEqual(emitted, true);
    });
  });
  
  describe('Rate limiting', () => {
    it('should enforce rate limits', async () => {
      const limitedModerator = new DharmaModerator({ maxChecksPerMinute: 5 });
      
      // Should allow up to limit
      for (let i = 0; i < 5; i++) {
        const result = await limitedModerator.checkContent('test ' + i);
        assert.ok(result);
      }
      
      // Should throw on exceeding
      try {
        await limitedModerator.checkContent('overflow');
        assert.fail('Should have thrown rate limit error');
      } catch (err) {
        assert.ok(err.message.includes('Rate limit'));
      }
    });
  });
  
  describe('getCategoryDocumentation()', () => {
    it('should return documentation without exposing patterns', () => {
      const docs = DharmaModerator.getCategoryDocumentation();
      
      assert.ok(docs.VIOLENCE_INCITEMENT);
      assert.ok(docs.VIOLENCE_INCITEMENT.description);
      assert.ok(docs.VIOLENCE_INCITEMENT.severity);
      
      // Should NOT expose actual keywords/patterns
      assert.strictEqual(docs.VIOLENCE_INCITEMENT.keywords, undefined);
      assert.strictEqual(docs.VIOLENCE_INCITEMENT.patterns, undefined);
    });
  });
});

// ============================================================
// MIDDLEWARE TESTS
// ============================================================

describe('createModerationMiddleware()', () => {
  it('should create middleware function', () => {
    const moderator = createDefaultModerator();
    const middleware = createModerationMiddleware(moderator);
    
    assert.strictEqual(typeof middleware, 'function');
  });
  
  it('should block harmful content', async () => {
    const moderator = createDefaultModerator();
    const middleware = createModerationMiddleware(moderator);
    
    const result = await middleware('Kill them all', {});
    
    assert.strictEqual(result.blocked, true);
    assert.ok(result.violations.length > 0);
  });
  
  it('should allow benign content and call next', async () => {
    const moderator = createDefaultModerator();
    const middleware = createModerationMiddleware(moderator);
    
    let nextCalled = false;
    const next = () => {
      nextCalled = true;
      return { allowed: true };
    };
    
    const result = await middleware('Hello world', {}, next);
    
    assert.strictEqual(nextCalled, true);
    assert.strictEqual(result.allowed, true);
  });
});

// ============================================================
// ANTI-DISCRIMINATION TESTS
// ============================================================

describe('Anti-Discrimination Verification', () => {
  let moderator;
  
  beforeEach(() => {
    moderator = new DharmaModerator();
  });
  
  it('should NOT block content based on religious identity mention', async () => {
    // These are mentions of religions, NOT calls for violence
    const religiousMentions = [
      'I am a Christian',
      'I practice Islam',
      'I follow Judaism',
      'I am Hindu',
      'I am Buddhist',
      'I practice Wicca',
      'I am pagan',
      'I am an atheist',
      'I am agnostic',
      'Our church meets on Sunday',
      'The mosque is beautiful',
      'The synagogue is historic',
      'The temple welcomes all',
    ];
    
    for (const content of religiousMentions) {
      const result = await moderator.checkContent(content);
      assert.strictEqual(
        result.allowed, 
        true,
        'Should NOT block religious identity: ' + content
      );
    }
  });
  
  it('should block calls to violence REGARDLESS of claimed motivation', async () => {
    // Violence is violence, regardless of who claims to do it
    const violentContent = [
      'As a believer, we must kill the unbelievers',
      'In the name of our god, death to them',
      'Our ancestors demand we exterminate them',
    ];
    
    for (const content of violentContent) {
      const result = await moderator.checkContent(content);
      assert.strictEqual(
        result.allowed, 
        false,
        'Should block violence regardless of claimed motivation: ' + content
      );
    }
  });
  
  it('should allow peaceful religious practices even if unfamiliar', async () => {
    const peacefulPractices = [
      'We gather under the full moon to celebrate',
      'Our ritual involves candles and incense',
      'We chant sacred words together',
      'We pray five times a day',
      'We observe the Sabbath',
      'We meditate on emptiness',
    ];
    
    for (const content of peacefulPractices) {
      const result = await moderator.checkContent(content);
      assert.strictEqual(
        result.allowed, 
        true,
        'Should allow peaceful practice: ' + content
      );
    }
  });
});

console.log('\\n=== DHARMA Content Moderation Tests ===');
console.log('Behavior-based filtering - NO identity discrimination');
console.log('Run with: node --test tests/dharma-moderation.test.js');
