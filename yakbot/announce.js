#!/usr/bin/env node

/**
 * YAKMESH Announcement Broadcaster
 * 
 * Sends announcements to Discord and Telegram channels.
 * 
 * Usage:
 *   node announce.js --version 2.6.0
 *   node announce.js --file announcements/telegram-v2.6.0.md --telegram
 *   node announce.js --message "Quick update: bug fix deployed" --all
 * 
 * @copyright 2026 YAKMESH™ Contributors
 */

import 'dotenv/config';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Configuration
const config = {
  // Discord webhook for announcements
  discordWebhook: process.env.DISCORD_WEBHOOK_URL,
  
  // Telegram bot token and channel
  telegramToken: process.env.TELEGRAM_BOT_TOKEN || '8503356631:AAESiZx7K6Ca78VfJh_sTqmsvTGgEXYDPEA',
  telegramChannel: process.env.TELEGRAM_CHANNEL_ID || '@yakmesh', // Channel username or chat ID
  
  // Announcements directory
  announcementsDir: join(__dirname, '..', 'announcements'),
};

/**
 * Send message to Discord via webhook
 */
async function sendToDiscord(message, options = {}) {
  if (!config.discordWebhook) {
    console.warn('⚠️  DISCORD_WEBHOOK_URL not set, skipping Discord');
    return { success: false, error: 'No webhook configured' };
  }

  try {
    const username = options.username || 'YakBot';
    const avatar_url = options.avatar || 'https://yakmesh.dev/assets/yakmesh-logo2.png';
    let payload;

    if (message.length <= 2000) {
      // Short messages: use content field directly
      payload = { content: message, username, avatar_url };
    } else {
      // Long messages: use embed (4096 char description limit)
      // Extract title from first markdown heading
      const titleMatch = message.match(/^#\s+(.+)$/m);
      const title = titleMatch ? titleMatch[1] : 'Yakmesh Announcement';
      const description = message.replace(/^#\s+.+\n+/, '').slice(0, 4096);
      payload = {
        username,
        avatar_url,
        embeds: [{
          title,
          description,
          color: 0x22c55e, // yakmesh green
          footer: { text: 'Sturdy & Secure 🦬' },
          timestamp: new Date().toISOString(),
        }],
      };
    }

    const response = await fetch(config.discordWebhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new Error(`Discord API error: ${response.status} ${body}`);
    }

    console.log('✅ Discord: Message sent');
    return { success: true };
  } catch (error) {
    console.error('❌ Discord:', error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Send message to Telegram channel
 */
async function sendToTelegram(message, options = {}) {
  try {
    const url = `https://api.telegram.org/bot${config.telegramToken}/sendMessage`;
    
    const payload = {
      chat_id: options.chatId || config.telegramChannel,
      text: message,
      parse_mode: 'Markdown',
      disable_web_page_preview: options.disablePreview || false,
    };

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    
    if (!data.ok) {
      throw new Error(data.description || 'Telegram API error');
    }

    console.log('✅ Telegram: Message sent to', payload.chat_id);
    return { success: true, messageId: data.result.message_id };
  } catch (error) {
    console.error('❌ Telegram:', error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Load announcement from file
 */
function loadAnnouncement(filename) {
  const filepath = filename.startsWith('/') || filename.includes(':') 
    ? filename 
    : join(config.announcementsDir, filename);
  
  if (!existsSync(filepath)) {
    throw new Error(`Announcement file not found: ${filepath}`);
  }
  
  let content = readFileSync(filepath, 'utf-8');
  
  // Remove markdown code fences if present
  content = content.replace(/^```markdown\n?/m, '').replace(/\n?```$/m, '');
  
  return content.trim();
}

/**
 * Parse command line arguments
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    version: null,
    file: null,
    message: null,
    discord: false,
    telegram: false,
    all: false,
    dryRun: false,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--version':
      case '-v':
        options.version = args[++i];
        break;
      case '--file':
      case '-f':
        options.file = args[++i];
        break;
      case '--message':
      case '-m':
        options.message = args[++i];
        break;
      case '--discord':
      case '-d':
        options.discord = true;
        break;
      case '--telegram':
      case '-t':
        options.telegram = true;
        break;
      case '--all':
      case '-a':
        options.all = true;
        break;
      case '--dry-run':
        options.dryRun = true;
        break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
    }
  }

  // Default to all platforms if none specified
  if (!options.discord && !options.telegram && !options.all) {
    options.all = true;
  }
  
  if (options.all) {
    options.discord = true;
    options.telegram = true;
  }

  return options;
}

function printHelp() {
  console.log(`
🏔️  YAKMESH Announcement Broadcaster

Usage:
  node announce.js [options]

Options:
  --version, -v <ver>   Load announcements for version (e.g., 2.6.0)
  --file, -f <file>     Load specific announcement file
  --message, -m <text>  Send custom message
  --discord, -d         Send to Discord only
  --telegram, -t        Send to Telegram only
  --all, -a             Send to all platforms (default)
  --dry-run             Preview without sending
  --help, -h            Show this help

Examples:
  node announce.js -v 2.6.0 --all
  node announce.js -f telegram-v2.6.0.md -t
  node announce.js -m "🚀 Hot fix deployed!" --all
  node announce.js -v 2.6.0 --dry-run
`);
}

/**
 * Main entry point
 */
async function main() {
  console.log('🏔️  YAKMESH Announcement Broadcaster\n');
  
  const options = parseArgs();
  const results = { discord: null, telegram: null };

  // Determine message content
  let discordMessage, telegramMessage;

  if (options.message) {
    discordMessage = options.message;
    telegramMessage = options.message;
  } else if (options.file) {
    telegramMessage = loadAnnouncement(options.file);
    discordMessage = telegramMessage;
  } else if (options.version) {
    // Load platform-specific announcements
    const discordFile = `discord-v${options.version}.md`;
    const telegramFile = `telegram-v${options.version}.md`;
    
    if (options.discord && existsSync(join(config.announcementsDir, discordFile))) {
      discordMessage = loadAnnouncement(discordFile);
    }
    if (options.telegram && existsSync(join(config.announcementsDir, telegramFile))) {
      telegramMessage = loadAnnouncement(telegramFile);
    }
    
    // Fall back to telegram format for both if discord-specific doesn't exist
    if (!discordMessage && telegramMessage) {
      discordMessage = telegramMessage;
    }
    if (!telegramMessage && discordMessage) {
      telegramMessage = discordMessage;
    }
  } else {
    console.error('❌ No message specified. Use --message, --file, or --version');
    process.exit(1);
  }

  if (options.dryRun) {
    console.log('📋 DRY RUN - Messages would be sent:\n');
    if (options.discord) {
      console.log('--- Discord ---');
      console.log(discordMessage || '(no message)');
      console.log();
    }
    if (options.telegram) {
      console.log('--- Telegram ---');
      console.log(telegramMessage || '(no message)');
    }
    return;
  }

  // Send to platforms
  if (options.discord && discordMessage) {
    results.discord = await sendToDiscord(discordMessage);
  }
  
  if (options.telegram && telegramMessage) {
    results.telegram = await sendToTelegram(telegramMessage);
  }

  // Summary
  console.log('\n📊 Summary:');
  if (results.discord) {
    console.log(`   Discord: ${results.discord.success ? '✅ Sent' : '❌ Failed'}`);
  }
  if (results.telegram) {
    console.log(`   Telegram: ${results.telegram.success ? '✅ Sent' : '❌ Failed'}`);
  }
}

main().catch(console.error);
