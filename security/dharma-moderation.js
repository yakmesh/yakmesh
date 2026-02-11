/**
 * DHARMA Content Moderation Module
 * 
 * Universal behavior-based content moderation for Yakmesh.
 * Filters ACTIONS, not IDENTITIES.
 * 
 * Philosophy:
 * - No religious, ethnic, or identity-based discrimination
 * - Focus on harmful BEHAVIORS: violence, exploitation, terrorism
 * - Transparent criteria published openly
 * - Host sovereignty: operators may extend locally
 * 
 * @module security/dharma-moderation.js
 * @version 3.0.0
 * @license MIT
 */

import { createHash } from 'crypto';
import { EventEmitter } from 'events';

// ============================================================
// PROHIBITED CONTENT CATEGORIES
// ============================================================

/**
 * Content categories that are universally prohibited.
 * These target BEHAVIORS and ACTIONS, not identities.
 */
export const PROHIBITED_CATEGORIES = Object.freeze({
  // Violence & Harm
  VIOLENCE_INCITEMENT: {
    id: 'violence-incitement',
    severity: 'critical',
    description: 'Content that directly incites violence against individuals or groups',
    keywords: [
      'kill them', 'murder them', 'exterminate', 'genocide', 'ethnic cleansing',
      'mass shooting', 'bomb them', 'eradicate', 'purge them'
    ],
    patterns: [
      /\b(kill|murder|shoot|stab|bomb)\s+(all|every|the)\s+\w+s?\b/i,
      /\bdeath\s+to\s+\w+\b/i,
    ]
  },
  
  TERRORISM_PROMOTION: {
    id: 'terrorism-promotion',
    severity: 'critical',
    description: 'Content that promotes, glorifies or recruits for terrorism',
    keywords: [
      'join isis', 'join al-qaeda', 'jihad against', 'martyrdom operation',
      'suicide bombing', 'terrorist attack', 'terror cell'
    ],
    patterns: [
      /\bterror(ist)?\s+(attack|cell|group|organization)\b/i,
      /\brecruit.*for.*terror/i,
    ]
  },
  
  WEAPONS_INSTRUCTIONS: {
    id: 'weapons-instructions',
    severity: 'high',
    description: 'Detailed instructions for creating weapons of mass harm',
    keywords: [
      'how to make bomb', 'pipe bomb instructions', 'ricin recipe',
      'anthrax creation', 'sarin synthesis', 'nerve agent'
    ],
    patterns: [
      /\bhow\s+to\s+(make|build|create)\s+(a\s+)?(bomb|explosive|poison)/i,
      /\b(detailed|step.by.step)\s+instructions?\s+for\s+(bomb|weapon)/i,
    ]
  },
  
  // Exploitation
  CHILD_EXPLOITATION: {
    id: 'child-exploitation',
    severity: 'critical',
    description: 'Any content that sexualizes or exploits minors',
    keywords: [
      'csam', 'child porn', 'pedo', 'minor explicit',
      'underage sex', 'child abuse material'
    ],
    patterns: [
      /\b(child|minor|underage)\s+(porn|sex|explicit|nude)/i,
      /\bcp\b.*\b(material|content|images)/i,
    ]
  },
  
  HUMAN_TRAFFICKING: {
    id: 'human-trafficking',
    severity: 'critical',
    description: 'Content facilitating human trafficking or slavery',
    keywords: [
      'buy slaves', 'sell humans', 'traffick women', 'traffick children',
      'sex slavery', 'forced labor market'
    ],
    patterns: [
      /\b(buy|sell|trade)\s+(slaves?|humans?|people)\b/i,
      /\btraffick(ing)?\s+(women|children|people)\b/i,
    ]
  },
  
  // Harmful Instructions
  SELF_HARM_PROMOTION: {
    id: 'self-harm-promotion',
    severity: 'high',
    description: 'Content that promotes or provides methods for self-harm or suicide',
    keywords: [
      'how to kill yourself', 'suicide methods', 'best way to die',
      'pro-ana', 'pro-mia', 'cutting tutorial'
    ],
    patterns: [
      /\bhow\s+to\s+(kill|end)\s+(yourself|your\s+life)/i,
      /\b(best|easy|painless)\s+(way|method)\s+to\s+die\b/i,
    ]
  },
  
  DOXXING: {
    id: 'doxxing',
    severity: 'high',
    description: 'Publishing private information to enable harassment',
    keywords: [
      'home address of', 'personal phone', 'doxx this person',
      'leak their info', 'find where they live'
    ],
    patterns: [
      /\b(doxx|dox)\s+(this|them|him|her)\b/i,
      /\bpost\s+(their|his|her)\s+(address|phone|ssn)\b/i,
    ]
  },
  
  // Fraud & Scams
  FINANCIAL_FRAUD: {
    id: 'financial-fraud',
    severity: 'medium',
    description: 'Content promoting financial scams or fraud schemes',
    keywords: [
      'steal credit cards', 'carding tutorial', 'phishing kit',
      'identity theft', 'bank fraud', 'money laundering'
    ],
    patterns: [
      /\b(steal|hack)\s+(credit\s+cards?|bank\s+accounts?)\b/i,
      /\b(carding|phishing)\s+(tutorial|guide|kit)\b/i,
    ]
  },
  
  // Specific Harmful Rituals
  HUMAN_SACRIFICE: {
    id: 'human-sacrifice',
    severity: 'critical',
    description: 'Content promoting or instructing human sacrifice rituals',
    keywords: [
      'human sacrifice ritual', 'blood sacrifice human', 'sacrificial killing',
      'ritual murder', 'sacrifice a person'
    ],
    patterns: [
      /\bhuman\s+sacrifice\b/i,
      /\bsacrifice\s+(a\s+)?(person|child|human|victim)\b/i,
      /\britual\s+(murder|killing|sacrifice)\b/i,
    ]
  },
});

/**
 * Severity levels for moderation actions
 */
export const SEVERITY_LEVELS = Object.freeze({
  CRITICAL: 'critical',  // Immediate block, report to authorities option
  HIGH: 'high',          // Block content, flag for review
  MEDIUM: 'medium',      // Flag for review, allow with warning
  LOW: 'low',            // Log only, allow
});

/**
 * Moderation actions
 */
export const MODERATION_ACTIONS = Object.freeze({
  BLOCK: 'block',        // Prevent content from being distributed
  FLAG: 'flag',          // Allow but mark for review
  WARN: 'warn',          // Allow with warning to user
  LOG: 'log',            // Silent logging only
  ALLOW: 'allow',        // No action
});

// ============================================================
// DHARMA MODERATOR CLASS
// ============================================================

/**
 * DharmaModerator - Universal behavior-based content moderation
 * 
 * Named after the concept of righteous conduct across traditions.
 * Enforces ethical behavior standards without religious discrimination.
 */
export class DharmaModerator extends EventEmitter {
  /**
   * Create a new DharmaModerator instance
   * @param {Object} config - Configuration options
   */
  constructor(config = {}) {
    super();
    
    this.config = {
      // Default severity thresholds
      blockThreshold: SEVERITY_LEVELS.HIGH,
      flagThreshold: SEVERITY_LEVELS.MEDIUM,
      
      // Enable/disable categories
      enabledCategories: Object.keys(PROHIBITED_CATEGORIES),
      
      // Custom patterns (host sovereignty)
      customPatterns: [],
      
      // Logging
      logLevel: 'info',
      
      // Rate limiting for moderation checks
      maxChecksPerMinute: 1000,
      
      ...config,
    };
    
    this.checkCount = 0;
    this.lastCheckReset = Date.now();
    
    // Build pattern index for performance
    this._buildPatternIndex();
  }
  
  /**
   * Build optimized pattern index from categories
   * @private
   */
  _buildPatternIndex() {
    this.patternIndex = new Map();
    
    for (const [categoryKey, category] of Object.entries(PROHIBITED_CATEGORIES)) {
      if (!this.config.enabledCategories.includes(categoryKey)) continue;
      
      // Add keyword patterns (word boundary wrapped)
      for (const keyword of category.keywords) {
        const pattern = new RegExp('\\b' + keyword.replace(/\s+/g, '\\s+') + '\\b', 'i');
        this.patternIndex.set(pattern, { category, match: 'keyword', original: keyword });
      }
      
      // Add regex patterns
      for (const pattern of category.patterns) {
        this.patternIndex.set(pattern, { category, match: 'pattern' });
      }
    }
    
    // Add custom patterns
    for (const custom of this.config.customPatterns) {
      this.patternIndex.set(
        custom.pattern, 
        { category: custom, match: 'custom' }
      );
    }
  }
  
  /**
   * Check content against moderation rules
   * @param {string} content - Content to check
   * @param {Object} context - Optional context (adapterId, userId, etc.)
   * @returns {Object} Moderation result
   */
  async checkContent(content, context = {}) {
    // Rate limiting
    this._checkRateLimit();
    
    if (!content || typeof content !== 'string') {
      return this._createResult(MODERATION_ACTIONS.ALLOW, null, content);
    }
    
    const normalizedContent = this._normalizeContent(content);
    const violations = [];
    
    // Check against all patterns
    for (const [pattern, info] of this.patternIndex) {
      if (pattern.test(normalizedContent)) {
        violations.push({
          categoryId: info.category.id,
          severity: info.category.severity,
          matchType: info.match,
          pattern: info.original || pattern.source,
          description: info.category.description,
        });
      }
    }
    
    // Determine action based on violations
    const result = this._determineAction(violations, content, context);
    
    // Emit events for logging/analysis
    if (result.action !== MODERATION_ACTIONS.ALLOW) {
      this.emit('violation', {
        result,
        context,
        timestamp: Date.now(),
        contentHash: this._hashContent(content),
      });
    }
    
    return result;
  }
  
  /**
   * Batch check multiple content items
   * @param {string[]} contents - Array of content strings
   * @param {Object} context - Shared context
   * @returns {Object[]} Array of moderation results
   */
  async checkBatch(contents, context = {}) {
    return Promise.all(
      contents.map(content => this.checkContent(content, context))
    );
  }
  
  /**
   * Normalize content for consistent matching
   * @private
   */
  _normalizeContent(content) {
    return content
      .toLowerCase()
      // Remove excessive whitespace
      .replace(/\s+/g, ' ')
      // Remove common obfuscation
      .replace(/[0-9@$!]/g, match => {
        const map = { '0': 'o', '@': 'a', '$': 's', '!': 'i', '1': 'i', '3': 'e' };
        return map[match] || match;
      })
      .trim();
  }
  
  /**
   * Create a moderation result object
   * @private
   */
  _createResult(action, violations, content) {
    return {
      action,
      allowed: action !== MODERATION_ACTIONS.BLOCK,
      violations: violations || [],
      violationCount: violations ? violations.length : 0,
      timestamp: Date.now(),
      checksum: this._hashContent(content || ''),
    };
  }
  
  /**
   * Determine appropriate action based on violations
   * @private
   */
  _determineAction(violations, content, context) {
    if (violations.length === 0) {
      return this._createResult(MODERATION_ACTIONS.ALLOW, [], content);
    }
    
    // Find highest severity
    const severityOrder = [
      SEVERITY_LEVELS.CRITICAL,
      SEVERITY_LEVELS.HIGH,
      SEVERITY_LEVELS.MEDIUM,
      SEVERITY_LEVELS.LOW,
    ];
    
    let highestSeverity = SEVERITY_LEVELS.LOW;
    for (const violation of violations) {
      const currentIndex = severityOrder.indexOf(violation.severity);
      const highestIndex = severityOrder.indexOf(highestSeverity);
      if (currentIndex < highestIndex) {
        highestSeverity = violation.severity;
      }
    }
    
    // Determine action based on severity
    let action;
    if (highestSeverity === SEVERITY_LEVELS.CRITICAL || 
        highestSeverity === SEVERITY_LEVELS.HIGH) {
      action = MODERATION_ACTIONS.BLOCK;
    } else if (highestSeverity === SEVERITY_LEVELS.MEDIUM) {
      action = MODERATION_ACTIONS.FLAG;
    } else {
      action = MODERATION_ACTIONS.WARN;
    }
    
    return {
      action,
      allowed: action !== MODERATION_ACTIONS.BLOCK,
      violations,
      violationCount: violations.length,
      highestSeverity,
      timestamp: Date.now(),
      checksum: this._hashContent(content),
    };
  }
  
  /**
   * Hash content for logging without storing actual content
   * @private
   */
  _hashContent(content) {
    return createHash('sha256')
      .update(content.substring(0, 1000))
      .digest('hex')
      .substring(0, 16);
  }
  
  /**
   * Check and enforce rate limits
   * @private
   */
  _checkRateLimit() {
    const now = Date.now();
    if (now - this.lastCheckReset > 60000) {
      this.checkCount = 0;
      this.lastCheckReset = now;
    }
    
    this.checkCount++;
    if (this.checkCount > this.config.maxChecksPerMinute) {
      throw new Error('Rate limit exceeded for moderation checks');
    }
  }
  
  /**
   * Add a custom pattern (host sovereignty feature)
   * @param {Object} pattern - Custom pattern definition
   */
  addCustomPattern(pattern) {
    if (!pattern.pattern || !pattern.severity || !pattern.id) {
      throw new Error('Custom pattern requires pattern, severity, and id');
    }
    
    this.config.customPatterns.push(pattern);
    this._buildPatternIndex();
    
    this.emit('patternAdded', { pattern });
  }
  
  /**
   * Get current moderation configuration
   * @returns {Object} Current configuration (sanitized)
   */
  getConfiguration() {
    return {
      enabledCategories: this.config.enabledCategories,
      blockThreshold: this.config.blockThreshold,
      flagThreshold: this.config.flagThreshold,
      customPatternCount: this.config.customPatterns.length,
      totalPatterns: this.patternIndex.size,
    };
  }
  
  /**
   * Get human-readable category descriptions
   * @returns {Object} Category documentation
   */
  static getCategoryDocumentation() {
    const docs = {};
    for (const [key, category] of Object.entries(PROHIBITED_CATEGORIES)) {
      docs[key] = {
        id: category.id,
        severity: category.severity,
        description: category.description,
        // Don't expose actual patterns publicly
      };
    }
    return docs;
  }
}

// ============================================================
// INTEGRATION HELPERS
// ============================================================

/**
 * Create a moderation middleware for adapters
 * @param {DharmaModerator} moderator - Moderator instance
 * @returns {Function} Middleware function
 */
export function createModerationMiddleware(moderator) {
  return async (content, context, next) => {
    const result = await moderator.checkContent(content, context);
    
    if (!result.allowed) {
      return {
        blocked: true,
        reason: 'Content violates community standards',
        violations: result.violations.map(v => ({
          category: v.categoryId,
          severity: v.severity,
        })),
      };
    }
    
    // Attach moderation result to context
    context.moderationResult = result;
    
    return next ? next(content, context) : { allowed: true };
  };
}

/**
 * Create a default moderator instance
 * @returns {DharmaModerator} Default moderator
 */
export function createDefaultModerator() {
  return new DharmaModerator();
}

// ============================================================
// EXPORTED CONSTANTS
// ============================================================

export default DharmaModerator;
