# MLV Bible Adapter for Yakmesh

Serve the Modern Literal Version Bible via DARSHAN streaming and enable scripture lookup in KATHA chat.

## Overview

This adapter demonstrates Yakmesh's **anti-censorship ethos** by enabling peer-to-peer scripture distribution without central servers or gatekeepers.

**\\For where two or three are gathered in my name, there am I among them.\\ - Matthew 18:20**

## Features

- **📖 PDF Streaming** - Serve MLV Bible PDFs via DARSHAN (view-not-copy paradigm)
- **🔍 Scripture Lookup** - Reference parser for all 66 books (e.g., \\John 3:16\\)
- **💬 Chat Commands** - \\/bible\\, \\/mlv\\, \\/verse\\, \\/scripture\\
- **🔐 Signed Quotes** - Verifiable scripture cards in chat
- **🌐 Decentralized** - Each user hosts their own copy

## Installation

\\\javascript
import { MLVBibleAdapter } from '@yakmesh/adapters/adapter-mlv-bible';

// Create adapter
const mlv = new MLVBibleAdapter({
  contentPath: './mlv-content',  // Path to your MLV PDFs
});

// Initialize
await mlv.init();

// Register with DARSHAN for streaming
await mlv.registerWithDarshan(darshan);

// Register with KATHA for chat commands
mlv.registerWithKatha(katha, chatModRegistry);
\\\

## Content Setup

1. Download MLV Bible from [modernliteralversion.org](https://www.modernliteralversion.org)
2. Place PDF files in your content directory
3. Optionally create a \\erses.json\\ for instant lookup:

\\\json
{
  \"John 3:16\": \"For God so loved the world...\",
  \"Genesis 1:1\": \"In the beginning God created...\"
}
\\\

## Chat Commands

| Command | Example | Description |
|---------|---------|-------------|
| \\/bible\\ | \\/bible John 3:16\\ | Look up a verse |
| \\/mlv\\ | \\/mlv Gen 1:1-5\\ | Look up a passage |
| \\/verse\\ | \\/verse Ps 23:1\\ | Look up a verse |
| \\/scripture\\ | \\/scripture Rom 8:28\\ | Look up a verse |

## Creating Your Own Scripture Adapter

This adapter serves as a template for other religious texts:

\\\javascript
import { ContentAdapter, CONTENT_CAPABILITIES } from '../content-adapter.js';
import { ChatModAdapter, ChatModManifest, CHAT_MOD_CAPABILITIES } from '../chat-mod-adapter.js';

class MyScriptureAdapter extends ContentAdapter {
  constructor(config) {
    super({
      name: 'My Scripture Name',
      id: 'my-scripture-id',
      capabilities: [
        CONTENT_CAPABILITIES.SERVE_PDF,
        CONTENT_CAPABILITIES.SEARCH_REFERENCE,
        CONTENT_CAPABILITIES.CHAT_QUOTE,
      ],
      ...config,
    });
  }

  async lookupReference(reference) {
    // Parse your reference format
    // Return { reference, text, ... }
  }
}
\\\

## Security Model

### Capability Declaration
Adapters MUST declare what they can do upfront:
- \\SERVE_PDF\\ - Can serve PDF content
- \\CHAT_QUOTE\\ - Can generate chat quotes
- \\CMD_SLASH\\ - Can handle slash commands

### Rate Limiting
Default: 30 messages per minute to prevent spam.

### Signed Responses
All adapter-generated content includes:
- Adapter ID and version
- Manifest hash for verification
- Timestamp

### No Raw Message Access
Chat adapters only receive sanitized context based on declared capabilities.

## Philosophy

Yakmesh rejects centralised gatekeeping of religious texts. This adapter embodies:

1. **Host Sovereignty** - You control your content
2. **No Central Server** - Peer-to-peer distribution
3. **Anti-Censorship** - No authority can block scripture
4. **Verification** - Mathematical proof replaces human trust

*\"Let the one who is thirsty come; and let the one who wishes take the free gift of the water of life.\"* - Revelation 22:17

## License

This adapter code is MIT licensed.
The Modern Literal Version Bible is in the public domain per [modernliteralversion.org](https://www.modernliteralversion.org).
