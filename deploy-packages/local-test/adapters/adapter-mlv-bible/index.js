/**
 * Yakmesh - Modern Literal Version Bible Adapter
 * 
 * Serves the Modern Literal Version Bible (https://www.modernliteralversion.org)
 * via DARSHAN streaming and provides scripture lookup for KATHA chat.
 * 
 * This adapter demonstrates:
 * 1. ContentAdapter for PDF/document serving
 * 2. ChatModAdapter for scripture commands (/bible, /mlv)
 * 3. Secure, verifiable scripture quoting in chat
 * 
 * SCRIPTURE SOVEREIGNTY: Users host their own scripture copies.
 * No central server, no censorship, no manipulation.
 * 
 * "For where two or three are gathered in my name, 
 *  there am I among them." - Matthew 18:20
 * 
 * @module adapters/adapter-mlv-bible
 * @version 1.0.0
 */

import { ContentAdapter, ContentMetadata, CONTENT_CAPABILITIES } from '../content-adapter.js';
import { ChatModAdapter, ChatModManifest, CHAT_MOD_CAPABILITIES } from '../chat-mod-adapter.js';
import { createReadStream, promises as fs } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Bible book metadata
 */
const BIBLE_BOOKS = {
  // Old Testament
  'Genesis': { abbrev: ['Gen', 'Ge'], chapters: 50, testament: 'OT' },
  'Exodus': { abbrev: ['Ex', 'Exod'], chapters: 40, testament: 'OT' },
  'Leviticus': { abbrev: ['Lev', 'Le'], chapters: 27, testament: 'OT' },
  'Numbers': { abbrev: ['Num', 'Nu'], chapters: 36, testament: 'OT' },
  'Deuteronomy': { abbrev: ['Deut', 'De'], chapters: 34, testament: 'OT' },
  'Joshua': { abbrev: ['Josh', 'Jos'], chapters: 24, testament: 'OT' },
  'Judges': { abbrev: ['Judg', 'Jdg'], chapters: 21, testament: 'OT' },
  'Ruth': { abbrev: ['Ruth', 'Ru'], chapters: 4, testament: 'OT' },
  '1 Samuel': { abbrev: ['1Sam', '1Sa'], chapters: 31, testament: 'OT' },
  '2 Samuel': { abbrev: ['2Sam', '2Sa'], chapters: 24, testament: 'OT' },
  '1 Kings': { abbrev: ['1Ki', '1Kgs'], chapters: 22, testament: 'OT' },
  '2 Kings': { abbrev: ['2Ki', '2Kgs'], chapters: 25, testament: 'OT' },
  '1 Chronicles': { abbrev: ['1Chr', '1Ch'], chapters: 29, testament: 'OT' },
  '2 Chronicles': { abbrev: ['2Chr', '2Ch'], chapters: 36, testament: 'OT' },
  'Ezra': { abbrev: ['Ezra', 'Ezr'], chapters: 10, testament: 'OT' },
  'Nehemiah': { abbrev: ['Neh', 'Ne'], chapters: 13, testament: 'OT' },
  'Esther': { abbrev: ['Est', 'Esth'], chapters: 10, testament: 'OT' },
  'Job': { abbrev: ['Job'], chapters: 42, testament: 'OT' },
  'Psalms': { abbrev: ['Ps', 'Psa', 'Psalm'], chapters: 150, testament: 'OT' },
  'Proverbs': { abbrev: ['Prov', 'Pr'], chapters: 31, testament: 'OT' },
  'Ecclesiastes': { abbrev: ['Ecc', 'Eccl'], chapters: 12, testament: 'OT' },
  'Song of Solomon': { abbrev: ['Song', 'SoS', 'SS'], chapters: 8, testament: 'OT' },
  'Isaiah': { abbrev: ['Isa', 'Is'], chapters: 66, testament: 'OT' },
  'Jeremiah': { abbrev: ['Jer', 'Je'], chapters: 52, testament: 'OT' },
  'Lamentations': { abbrev: ['Lam', 'La'], chapters: 5, testament: 'OT' },
  'Ezekiel': { abbrev: ['Ezek', 'Eze'], chapters: 48, testament: 'OT' },
  'Daniel': { abbrev: ['Dan', 'Da'], chapters: 12, testament: 'OT' },
  'Hosea': { abbrev: ['Hos', 'Ho'], chapters: 14, testament: 'OT' },
  'Joel': { abbrev: ['Joel', 'Joe'], chapters: 3, testament: 'OT' },
  'Amos': { abbrev: ['Amos', 'Am'], chapters: 9, testament: 'OT' },
  'Obadiah': { abbrev: ['Obad', 'Ob'], chapters: 1, testament: 'OT' },
  'Jonah': { abbrev: ['Jonah', 'Jon'], chapters: 4, testament: 'OT' },
  'Micah': { abbrev: ['Mic', 'Mi'], chapters: 7, testament: 'OT' },
  'Nahum': { abbrev: ['Nah', 'Na'], chapters: 3, testament: 'OT' },
  'Habakkuk': { abbrev: ['Hab'], chapters: 3, testament: 'OT' },
  'Zephaniah': { abbrev: ['Zeph', 'Zep'], chapters: 3, testament: 'OT' },
  'Haggai': { abbrev: ['Hag'], chapters: 2, testament: 'OT' },
  'Zechariah': { abbrev: ['Zech', 'Zec'], chapters: 14, testament: 'OT' },
  'Malachi': { abbrev: ['Mal'], chapters: 4, testament: 'OT' },
  
  // New Testament
  'Matthew': { abbrev: ['Matt', 'Mt'], chapters: 28, testament: 'NT' },
  'Mark': { abbrev: ['Mark', 'Mk'], chapters: 16, testament: 'NT' },
  'Luke': { abbrev: ['Luke', 'Lk'], chapters: 24, testament: 'NT' },
  'John': { abbrev: ['John', 'Jn'], chapters: 21, testament: 'NT' },
  'Acts': { abbrev: ['Acts', 'Ac'], chapters: 28, testament: 'NT' },
  'Romans': { abbrev: ['Rom', 'Ro'], chapters: 16, testament: 'NT' },
  '1 Corinthians': { abbrev: ['1Cor', '1Co'], chapters: 16, testament: 'NT' },
  '2 Corinthians': { abbrev: ['2Cor', '2Co'], chapters: 13, testament: 'NT' },
  'Galatians': { abbrev: ['Gal', 'Ga'], chapters: 6, testament: 'NT' },
  'Ephesians': { abbrev: ['Eph'], chapters: 6, testament: 'NT' },
  'Philippians': { abbrev: ['Phil', 'Php'], chapters: 4, testament: 'NT' },
  'Colossians': { abbrev: ['Col'], chapters: 4, testament: 'NT' },
  '1 Thessalonians': { abbrev: ['1Thess', '1Th'], chapters: 5, testament: 'NT' },
  '2 Thessalonians': { abbrev: ['2Thess', '2Th'], chapters: 3, testament: 'NT' },
  '1 Timothy': { abbrev: ['1Tim', '1Ti'], chapters: 6, testament: 'NT' },
  '2 Timothy': { abbrev: ['2Tim', '2Ti'], chapters: 4, testament: 'NT' },
  'Titus': { abbrev: ['Titus', 'Tit'], chapters: 3, testament: 'NT' },
  'Philemon': { abbrev: ['Phlm', 'Phm'], chapters: 1, testament: 'NT' },
  'Hebrews': { abbrev: ['Heb'], chapters: 13, testament: 'NT' },
  'James': { abbrev: ['Jas', 'Jam'], chapters: 5, testament: 'NT' },
  '1 Peter': { abbrev: ['1Pet', '1Pe'], chapters: 5, testament: 'NT' },
  '2 Peter': { abbrev: ['2Pet', '2Pe'], chapters: 3, testament: 'NT' },
  '1 John': { abbrev: ['1Jn', '1Jo'], chapters: 5, testament: 'NT' },
  '2 John': { abbrev: ['2Jn', '2Jo'], chapters: 1, testament: 'NT' },
  '3 John': { abbrev: ['3Jn', '3Jo'], chapters: 1, testament: 'NT' },
  'Jude': { abbrev: ['Jude'], chapters: 1, testament: 'NT' },
  'Revelation': { abbrev: ['Rev', 'Re'], chapters: 22, testament: 'NT' },
};

/**
 * Parse a scripture reference (e.g., \"John 3:16\" or \"Gen 1:1-5\")
 */
function parseReference(ref) {
  // Pattern: Book Chapter:Verse(-EndVerse)?
  const pattern = /^(\d?\s*[A-Za-z]+)\s*(\d+):(\d+)(?:-(\d+))?$/;
  const match = ref.trim().match(pattern);
  
  if (!match) return null;
  
  const [, bookPart, chapter, startVerse, endVerse] = match;
  const bookName = bookPart.trim();
  
  // Find the book
  let foundBook = null;
  for (const [name, data] of Object.entries(BIBLE_BOOKS)) {
    if (name.toLowerCase() === bookName.toLowerCase() ||
        data.abbrev.some(a => a.toLowerCase() === bookName.toLowerCase())) {
      foundBook = { name, ...data };
      break;
    }
  }
  
  if (!foundBook) return null;
  
  return {
    book: foundBook.name,
    chapter: parseInt(chapter, 10),
    startVerse: parseInt(startVerse, 10),
    endVerse: endVerse ? parseInt(endVerse, 10) : parseInt(startVerse, 10),
    testament: foundBook.testament,
  };
}

/**
 * MLV Bible Content Adapter
 * Serves PDF files and handles scripture lookup
 */
export class MLVContentAdapter extends ContentAdapter {
  constructor(config = {}) {
    super({
      name: 'Modern Literal Version Bible',
      id: 'mlv-bible-content',
      capabilities: [
        CONTENT_CAPABILITIES.SERVE_PDF,
        CONTENT_CAPABILITIES.SERVE_TEXT,
        CONTENT_CAPABILITIES.SEARCH_REFERENCE,
        CONTENT_CAPABILITIES.CHAT_QUOTE,
        CONTENT_CAPABILITIES.CHAT_LOOKUP,
        CONTENT_CAPABILITIES.NET_STREAM,
      ],
      ...config,
    });
    
    // Path to MLV content files
    this.contentPath = config.contentPath || join(__dirname, 'content');
    
    // In-memory verse index (populated on init)
    this.verseIndex = new Map();  // \"John 3:16\" -> verse text
  }
  
  async init() {
    // Register PDF files
    try {
      const files = await fs.readdir(this.contentPath);
      
      for (const file of files) {
        if (file.endsWith('.pdf')) {
          const filePath = join(this.contentPath, file);
          const stat = await fs.stat(filePath);
          
          const id = file.replace('.pdf', '');
          this.catalog.set(id, new ContentMetadata({
            id,
            title: this._formatTitle(id),
            author: 'Modern Literal Version Translation Committee',
            copyright: 'Public Domain / MLV License',
            license: 'Free to distribute - https://www.modernliteralversion.org',
            contentType: 'application/pdf',
            size: stat.size,
            created: stat.birthtime,
            modified: stat.mtime,
            tags: ['bible', 'scripture', 'mlv', 'christianity'],
          }));
        }
        
        // Load verse JSON index if present
        if (file === 'verses.json') {
          const data = await fs.readFile(join(this.contentPath, file), 'utf8');
          const verses = JSON.parse(data);
          for (const [ref, text] of Object.entries(verses)) {
            this.verseIndex.set(ref.toLowerCase(), { ref, text });
          }
        }
      }
    } catch (err) {
      // Content directory might not exist yet - that's okay
      console.log('[MLV] No content directory found. Create:', this.contentPath);
    }
    
    this.emit('initialized', { catalogSize: this.catalog.size });
  }
  
  _formatTitle(id) {
    // Convert \"mlv-nt\" to \"MLV New Testament\", etc.
    return id
      .replace('mlv-', 'MLV ')
      .replace('nt', 'New Testament')
      .replace('ot', 'Old Testament')
      .replace('complete', 'Complete Bible');
  }
  
  async search(query, options = {}) {
    this.stats.searchQueries++;
    
    const results = [];
    const q = query.toLowerCase();
    
    for (const [ref, data] of this.verseIndex) {
      if (ref.includes(q) || data.text.toLowerCase().includes(q)) {
        results.push({
          reference: data.ref,
          text: data.text,
          score: ref.includes(q) ? 1.0 : 0.5,
        });
        
        if (results.length >= (options.limit || 20)) break;
      }
    }
    
    return results.sort((a, b) => b.score - a.score);
  }
  
  async lookupReference(reference) {
    const parsed = parseReference(reference);
    if (!parsed) return null;
    
    // Build the lookup key
    const key = \\ \:\\;
    
    // Check verse index
    const verse = this.verseIndex.get(key);
    if (verse) {
      return {
        reference: \\ \:\\,
        text: verse.text,
        book: parsed.book,
        chapter: parsed.chapter,
        verse: parsed.startVerse,
        testament: parsed.testament,
      };
    }
    
    // If not in index, return a placeholder indicating lookup needed
    return {
      reference: \\ \:\\,
      text: '[Verse text available in PDF - download MLV from modernliteralversion.org]',
      book: parsed.book,
      chapter: parsed.chapter,
      verse: parsed.startVerse,
      testament: parsed.testament,
      needsFullContent: true,
    };
  }
  
  async getContentStream(id, options = {}) {
    const meta = this.catalog.get(id);
    if (!meta) {
      throw new Error('Content not found: ' + id);
    }
    
    const filePath = join(this.contentPath, id + '.pdf');
    this.stats.contentServed++;
    
    return createReadStream(filePath, {
      start: options.start || 0,
      end: options.end,
    });
  }
}

/**
 * MLV Bible Chat Mod Adapter
 * Handles /bible and /mlv commands in KATHA chat
 */
export class MLVChatAdapter extends ChatModAdapter {
  constructor(contentAdapter, config = {}) {
    super(
      new ChatModManifest({
        id: 'mlv-bible-chat',
        name: 'MLV Bible Chat',
        version: '1.0.0',
        author: 'Yakmesh Community',
        description: 'Scripture lookup and sharing in chat. Commands: /bible, /mlv',
        capabilities: [
          CHAT_MOD_CAPABILITIES.CMD_SLASH,
          CHAT_MOD_CAPABILITIES.MSG_RESPOND,
          CHAT_MOD_CAPABILITIES.GEN_QUOTE,
          CHAT_MOD_CAPABILITIES.GEN_CARD,
        ],
        commands: ['bible', 'mlv', 'scripture', 'verse'],
        triggers: [],  // Only respond to explicit commands
        rateLimit: { messages: 30, window: 60000 },  // 30/min for scripture
      }),
      config
    );
    
    this.contentAdapter = contentAdapter;
  }
  
  async init() {
    await this.contentAdapter.init();
    this.emit('initialized');
  }
  
  async onCommand(command, args, context) {
    const reference = args.join(' ');
    
    if (!reference) {
      return {
        type: 'text',
        content: \Usage: /\ <reference>\nExample: /\ John 3:16\,
      };
    }
    
    const result = await this.contentAdapter.lookupReference(reference);
    
    if (!result) {
      return {
        type: 'text',
        content: \Could not find: \\nCheck the format: Book Chapter:Verse (e.g., John 3:16)\,
      };
    }
    
    // Return a rich scripture card
    return {
      type: 'scripture-card',
      reference: result.reference,
      text: result.text,
      translation: 'Modern Literal Version',
      source: 'https://www.modernliteralversion.org',
      testament: result.testament,
      metadata: {
        adapterId: this.manifest.id,
        timestamp: Date.now(),
      },
    };
  }
}

/**
 * Combined MLV Bible Adapter
 * Convenience class that bundles content + chat functionality
 */
export class MLVBibleAdapter {
  constructor(config = {}) {
    this.contentAdapter = new MLVContentAdapter(config);
    this.chatAdapter = new MLVChatAdapter(this.contentAdapter, config);
  }
  
  async init() {
    await this.contentAdapter.init();
    // Chat adapter shares the content adapter's data
  }
  
  /**
   * Register with a DARSHAN instance for content streaming
   */
  async registerWithDarshan(darshan) {
    this.contentAdapter.darshan = darshan;
    
    // Register all PDF content
    for (const [id] of this.contentAdapter.catalog) {
      await this.contentAdapter.registerWithDarshan(id, {
        allowDownload: true,  // MLV is freely distributable
      });
    }
  }
  
  /**
   * Register with KATHA chat for commands
   */
  registerWithKatha(katha, registry) {
    registry.register(this.chatAdapter);
    this.chatAdapter.katha = katha;
  }
  
  getStats() {
    return {
      content: this.contentAdapter.getStats(),
      chat: this.chatAdapter.getStats(),
    };
  }
}

export default MLVBibleAdapter;
