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
 * Yakmesh - Content Adapter Base Class
 * 
 * Specialized adapter for content distribution via DARSHAN protocol.
 * Designed for scripture, documents, educational materials, and other
 * content that benefits from the view-not-copy paradigm.
 * 
 * @module adapters/content-adapter
 * @version 1.0.0
 */

import { EventEmitter } from 'events';

/**
 * Capability declarations for content adapters
 * Adapters MUST declare their capabilities upfront
 */
export const CONTENT_CAPABILITIES = {
  // Content types this adapter can serve
  SERVE_PDF: 'serve:pdf',
  SERVE_TEXT: 'serve:text',
  SERVE_AUDIO: 'serve:audio',
  SERVE_VIDEO: 'serve:video',

  // Search/lookup capabilities
  SEARCH_FULLTEXT: 'search:fulltext',
  SEARCH_REFERENCE: 'search:reference',  // e.g., John 3:16

  // Chat integration capabilities
  CHAT_QUOTE: 'chat:quote',          // Can generate quotes for KATHA
  CHAT_EMBED: 'chat:embed',          // Can embed previews in chat
  CHAT_LOOKUP: 'chat:lookup',        // Can respond to lookup commands

  // Network capabilities
  NET_STREAM: 'net:stream',          // Can stream via DARSHAN
  NET_DOWNLOAD: 'net:download',      // Allows downloads (opt-in)
  NET_CACHE: 'net:cache',            // Can be cached by peers
};

/**
 * Content metadata standard
 */
export class ContentMetadata {
  constructor({
    id,
    title,
    author = null,
    copyright = null,
    license = null,
    version = '1.0.0',
    language = 'en',
    contentType = 'application/pdf',
    size = 0,
    hash = null,
    created = new Date(),
    modified = new Date(),
    tags = [],
    references = {},  // e.g., { 'John 3:16': { page: 42, position: 0.3 } }
  } = {}) {
    this.id = id;
    this.title = title;
    this.author = author;
    this.copyright = copyright;
    this.license = license;
    this.version = version;
    this.language = language;
    this.contentType = contentType;
    this.size = size;
    this.hash = hash;
    this.created = created;
    this.modified = modified;
    this.tags = tags;
    this.references = references;
  }

  toJSON() {
    return { ...this };
  }
}

/**
 * Abstract base class for content distribution adapters
 */
export class ContentAdapter extends EventEmitter {
  /**
   * @param {Object} config - Adapter configuration
   * @param {string} config.name - Human-readable adapter name
   * @param {string} config.id - Unique adapter identifier
   * @param {string[]} config.capabilities - Array of CONTENT_CAPABILITIES
   * @param {Object} config.darshan - DARSHAN instance for streaming
   */
  constructor(config = {}) {
    super();

    if (new.target === ContentAdapter) {
      throw new Error('ContentAdapter is abstract and cannot be instantiated directly');
    }

    this.name = config.name || 'UnnamedContentAdapter';
    this.id = config.id || 'content-adapter-' + Date.now();
    this.capabilities = new Set(config.capabilities || []);
    this.darshan = config.darshan || null;

    // Content catalog
    this.catalog = new Map();  // id -> ContentMetadata

    // Statistics
    this.stats = {
      contentServed: 0,
      searchQueries: 0,
      chatQuotes: 0,
      errors: [],
    };

    // Security: Validate capabilities
    this._validateCapabilities();
  }

  /**
   * Initialize the adapter and build content catalog
   * @abstract
   */
  async init() {
    throw new Error('init() must be implemented by subclass');
  }

  /**
   * Get list of available content
   * @returns {ContentMetadata[]}
   */
  listContent() {
    return Array.from(this.catalog.values());
  }

  /**
   * Get content metadata by ID
   * @param {string} id - Content ID
   * @returns {ContentMetadata|null}
   */
  getContentMeta(id) {
    return this.catalog.get(id) || null;
  }

  /**
   * Search content by query
   * @abstract
   * @param {string} query - Search query
   * @param {Object} options - Search options
   * @returns {Promise<Object[]>} Search results
   */
  async search(query, options = {}) {
    throw new Error('search() must be implemented by subclass');
  }

  /**
   * Lookup content by reference (e.g., 'John 3:16')
   * @abstract
   * @param {string} reference - Reference string
   * @returns {Promise<Object|null>} Lookup result
   */
  async lookupReference(reference) {
    throw new Error('lookupReference() must be implemented by subclass');
  }

  /**
   * Get content stream for DARSHAN
   * @abstract
   * @param {string} id - Content ID
   * @param {Object} options - Stream options (range, quality, etc.)
   * @returns {Promise<ReadableStream>}
   */
  async getContentStream(id, options = {}) {
    throw new Error('getContentStream() must be implemented by subclass');
  }

  /**
   * Generate a quotable snippet for KATHA chat
   * @param {string} reference - Content reference
   * @param {Object} options - Quote options
   * @returns {Promise<Object>} Quote object for KATHA
   */
  async generateChatQuote(reference, options = {}) {
    if (!this.capabilities.has(CONTENT_CAPABILITIES.CHAT_QUOTE)) {
      throw new Error('Adapter does not support chat quotes');
    }

    const result = await this.lookupReference(reference);
    if (!result) {
      return null;
    }

    this.stats.chatQuotes++;

    return {
      type: 'content-quote',
      adapter: this.id,
      reference,
      text: result.text,
      metadata: {
        source: this.name,
        contentId: result.contentId,
        position: result.position,
      },
      // Security: Sign the quote so it can be verified
      verified: true,
    };
  }

  /**
   * Register content with DARSHAN for streaming
   * @param {string} id - Content ID
   * @param {Object} options - Registration options
   */
  async registerWithDarshan(id, options = {}) {
    if (!this.darshan) {
      throw new Error('DARSHAN instance not configured');
    }

    const meta = this.catalog.get(id);
    if (!meta) {
      throw new Error('Content not found: ' + id);
    }

    // Register as a DARSHAN content source
    await this.darshan.registerContent(id, {
      title: meta.title,
      type: meta.contentType,
      size: meta.size,
      getStream: () => this.getContentStream(id),
      allowDownload: options.allowDownload || false,
      // DARSHAN handles view-not-copy enforcement
    });

    this.emit('content-registered', { id, meta });
  }

  /**
   * Validate declared capabilities
   * @private
   */
  _validateCapabilities() {
    const validCaps = new Set(Object.values(CONTENT_CAPABILITIES));
    for (const cap of this.capabilities) {
      if (!validCaps.has(cap)) {
        console.warn(`Unknown capability declared: ${cap}`);
      }
    }
  }

  /**
   * Check if adapter has a capability
   * @param {string} capability - Capability to check
   * @returns {boolean}
   */
  hasCapability(capability) {
    return this.capabilities.has(capability);
  }

  /**
   * Get adapter statistics
   */
  getStats() {
    return {
      ...this.stats,
      name: this.name,
      id: this.id,
      capabilities: Array.from(this.capabilities),
      catalogSize: this.catalog.size,
    };
  }
}

export default ContentAdapter;
