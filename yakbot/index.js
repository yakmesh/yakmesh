/**
 * YakBot - YAKMESH™ Discord Community Bot
 * 
 * Features:
 * - /status - Show current version, links
 * - /docs [topic] - Quick documentation links
 * - /changelog - Recent changes
 * - /ask [question] - AI-powered Q&A about YAKMESH
 * - /nodes - Check health of official YAKMESH nodes
 * - /faq - Frequently asked questions
 * - /ping - Bot latency check
 * - Auto-greet new members
 * 
 * @copyright 2026 YAKMESH™ Contributors
 */

import { Client, GatewayIntentBits, EmbedBuilder, Events, Partials } from 'discord.js';
import { GoogleGenerativeAI } from '@google/generative-ai';
import 'dotenv/config';
import { createLogger } from './utils/logger.js';

const log = createLogger('yakbot:main');

// Configuration
const config = {
  // Discord bot token (from Discord Developer Portal)
  token: process.env.DISCORD_TOKEN,
  
  // Gemini API key for AI responses
  geminiKey: process.env.GEMINI_API_KEY,
  
  // Current version
  version: '2.6.0',
  
  // Official YAKMESH nodes for health checks
  officialNodes: [
    { name: 'Primary (Hostinger)', url: 'https://yakmesh.dev/node.php?e=health', icon: '🦬' },
    { name: 'LAN (Abyss)', url: 'http://192.168.1.178:3000/health', icon: '🏠' },
  ],
  
  // Links
  links: {
    github: 'https://github.com/yakmesh/yakmesh',
    npm: 'https://npmjs.com/package/yakmesh',
    docs: 'https://yakmesh.dev/docs',
    website: 'https://yakmesh.dev',
    discord: 'https://discord.gg/8mSPfbJB8N',
    twitter: 'https://x.com/yakmesh_dev',
    telegram: 'https://t.me/yakmesh',
    patreon: 'https://patreon.com/yakmesh',
  },
  
  // Brand colors
  colors: {
    primary: 0x13B583,    // Yakmesh green
    success: 0x10B981,
    warning: 0xF59E0B,
    error: 0xEF4444,
    info: 0x3B82F6,
  },
};

// YAKMESH knowledge base for AI context
const YAKMESH_CONTEXT = `
You are YakBot, the helpful assistant for YAKMESH™ v2.6.0 - a post-quantum secure P2P mesh network.

Key facts about YAKMESH:
- YAKMESH stands for: Yielding Atomic Kernel Modular Encryption Secured Hub
- Current version: ${config.version}
- Written in Node.js/JavaScript (ESM modules)
- Uses ML-DSA-65 (NIST FIPS 204) for post-quantum signatures
- Uses ML-KEM-768 (NIST FIPS 203) for quantum-resistant key exchange
- Self-verifying oracle for deterministic validation
- Content-addressed storage with SHA3-256 hashing
- Gossip protocol for message propagation
- WebSocket-based mesh networking
- 732+ tests covering oracle, protocol, security, and mesh modules

NAMCHE 7-Gate Identity Verification:
Nodes pass through 7 mathematical gates for cryptographic identity proof:
1. CRYPTO - ML-DSA-65 signature verification
2. TEMPORAL - Challenge/response timing analysis
3. BEHAVIORAL - Pattern consistency over time
4. HARDWARE - AES-NI timing attestation (≤2 cycles/byte = real silicon, emulators 10-50x slower)
5. NETWORK - Latency fingerprinting
6. GEOGRAPHIC - Speed-of-light location proof (199,861.639 km/s in fiber, ±50km precision)
7. SOCIAL - Cross-node vouching from Guardians

Each gate returns confidence scores. Cross 5+ gates = cryptographically verified.

Trust Tiers:
- UNTRUSTED (0) - New nodes, limited capabilities
- PENDING (1) - Completing verification challenges
- VERIFIED (2) - Passed basic verification (5+ gates)
- TRUSTED (3) - Proven reliable over time
- GUARDIAN (4) - Highly trusted, can vouch for others, anchor the network

Security Features:
- NAMCHE Gateway: 7-gate mathematical verification (no human authority)
- DOKO Identity: Distributed Ownership & Key Objects for identity management
- iO Obfuscation: All user-facing identifiers use indistinguishability obfuscation
- TLS Binding: Certificate fingerprints bound to DOKO identities
- Phase Epochs: Time-based replay protection with 6-hour epochs
- Geographic Proof: Speed-of-light physics prove minimum node distances (triangulation from 3+ verifiers)
- Hardware Attestation: AES-NI instruction timing proves real silicon vs VMs
- Strike System: Bad behavior = strikes → ban
- Sybil Detection: Prevents fake identity floods
- Mesh Revocation: Network-wide key revocation

Protocol Stack (top to bottom):
1. YAK:// Protocol - Custom URL scheme (yak://dashboard, yak://site, etc.)
2. HTTP API - Public content delivery (CDN layer)
3. Annex - Encrypted point-to-point messaging (ML-KEM-768 + XChaCha20-Poly1305)
4. Gossip - Epidemic-style message propagation with rumors
5. Beacon - Emergency broadcast with priority levels
6. Nakpak - Onion routing for anonymity (Nested Anonymous Kernel for Private Authenticated Komms)
7. Sherpa - Peer discovery DHT with RTT geo-proofing (Secure Hidden Endpoint Resolution Path Architecture)
8. Mesh - Core P2P network with Code Proof Protocol

Installation:
npm install yakmesh

Quick Start:
npx yakmesh init
npx yakmesh start

Links:
- GitHub: ${config.links.github}
- npm: ${config.links.npm}
- Docs: ${config.links.docs}
- Website: ${config.links.website}

Be helpful, concise, and friendly. Use emojis occasionally. If you don't know something specific about YAKMESH, say so and suggest checking the documentation.
`;

// Initialize Discord client
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.DirectMessages,
  ],
  partials: [
    Partials.Channel,  // Required for DM channels
    Partials.Message,  // Required for DM messages
  ],
});

// Bot statistics tracking
const stats = {
  startTime: Date.now(),
  messagesReceived: 0,
  commandsProcessed: 0,
  aiQueriesProcessed: 0,
  mentionsProcessed: 0,
  errors: 0,
};

// Initialize Gemini AI
let genAI = null;
let model = null;

if (config.geminiKey) {
  genAI = new GoogleGenerativeAI(config.geminiKey);
  model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });
  log.info('Gemini AI initialized');
}

// Helper to create embeds
function createEmbed(options) {
  const embed = new EmbedBuilder()
    .setColor(options.color || config.colors.primary)
    .setTimestamp();
    
  if (options.title) embed.setTitle(options.title);
  if (options.description) embed.setDescription(options.description);
  if (options.fields) embed.addFields(options.fields);
  if (options.footer) embed.setFooter({ text: options.footer, iconURL: 'https://raw.githubusercontent.com/yakmesh/yakmesh/main/assets/yakmesh-logo2.png' });
  if (options.thumbnail) embed.setThumbnail(options.thumbnail);
  if (options.url) embed.setURL(options.url);
  
  return embed;
}

// Fetch npm stats
async function getNpmStats() {
  try {
    const response = await fetch('https://registry.npmjs.org/yakmesh');
    const data = await response.json();
    return {
      version: data['dist-tags']?.latest || config.version,
      versions: Object.keys(data.versions || {}).length,
    };
  } catch (e) {
    return { version: config.version, versions: '?' };
  }
}

// Fetch GitHub stats
async function getGitHubStats() {
  try {
    const response = await fetch('https://api.github.com/repos/yakmesh/yakmesh');
    const data = await response.json();
    return {
      stars: data.stargazers_count || 0,
      forks: data.forks_count || 0,
      issues: data.open_issues_count || 0,
    };
  } catch (e) {
    return { stars: '?', forks: '?', issues: '?' };
  }
}

// Check node health
async function checkNodeHealth(nodeUrl) {
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000); // 5s timeout
    
    // Use the URL directly (it may already include the health endpoint)
    const response = await fetch(nodeUrl, { 
      signal: controller.signal,
      headers: { 'Accept': 'application/json' }
    });
    
    clearTimeout(timeout);
    const latency = Date.now() - start;
    
    if (response.ok) {
      // Try to get version info if available
      let version = null;
      let peers = null;
      let content = null;
      let algorithm = null;
      let networkName = null;
      
      try {
        const data = await response.json();
        version = data.version;
        peers = data.peers ?? data.peerCount ?? null;
        content = data.content ?? data.contentCount ?? null;
        algorithm = data.algorithm;
        networkName = data.network?.name;
      } catch {
        // Not JSON, that's OK
      }
      
      return {
        online: true,
        latency,
        version,
        peers,
        content,
        algorithm,
        networkName,
        status: response.status,
      };
    } else {
      return {
        online: false,
        latency,
        status: response.status,
        error: `HTTP ${response.status}`,
      };
    }
  } catch (error) {
    return {
      online: false,
      latency: Date.now() - start,
      error: error.name === 'AbortError' ? 'Timeout' : error.message,
    };
  }
}

// Command handlers
const commands = {
  // /status - Show current status
  async status(interaction) {
    await interaction.deferReply();
    
    const [npm, github] = await Promise.all([getNpmStats(), getGitHubStats()]);
    
    const embed = createEmbed({
      title: '🦬 YAKMESH™ Status',
      description: 'Sturdy & Secure - Post-quantum P2P mesh network',
      thumbnail: 'https://raw.githubusercontent.com/yakmesh/yakmesh/main/assets/yakmesh-logo2.png',
      fields: [
        { name: '📦 Version', value: `\`${npm.version}\``, inline: true },
        { name: '⭐ Stars', value: `${github.stars}`, inline: true },
        { name: '🍴 Forks', value: `${github.forks}`, inline: true },
        { name: '🔐 Cryptography', value: 'ML-DSA-65 + ML-KEM768', inline: true },
        { name: '📊 Releases', value: `${npm.versions}`, inline: true },
        { name: '🐛 Issues', value: `${github.issues}`, inline: true },
        { name: '🔗 Links', value: `[Website](${config.links.website}) • [GitHub](${config.links.github}) • [npm](${config.links.npm}) • [Docs](${config.links.docs})`, inline: false },
      ],
      footer: 'YAKMESH™ - Yielding Atomic Kernel Modular Encryption Secured Hub',
    });
    
    await interaction.editReply({ embeds: [embed] });
  },
  
  // /nodes - Check official node health
  async nodes(interaction) {
    await interaction.deferReply();
    
    const results = await Promise.all(
      config.officialNodes.map(async (node) => {
        const health = await checkNodeHealth(node.url);
        return { ...node, ...health };
      })
    );
    
    const fields = results.map(node => {
      const statusIcon = node.online ? '🟢' : '🔴';
      const latencyText = node.online ? `${node.latency}ms` : 'N/A';
      
      let value = `${statusIcon} **${node.online ? 'Online' : 'Offline'}**\n`;
      value += `⏱️ Latency: ${latencyText}\n`;
      
      if (node.algorithm) value += `🔐 ${node.algorithm}\n`;
      if (node.networkName) value += `🌐 ${node.networkName}\n`;
      if (node.peers !== null && node.peers !== undefined) value += `👥 Peers: ${node.peers}\n`;
      if (!node.online && node.error) value += `❌ Error: ${node.error}\n`;
      
      return {
        name: `${node.icon} ${node.name}`,
        value,
        inline: true,
      };
    });
    
    const allOnline = results.every(n => n.online);
    const someOnline = results.some(n => n.online);
    
    let statusText, statusColor;
    if (allOnline) {
      statusText = '✅ All nodes operational';
      statusColor = config.colors.success;
    } else if (someOnline) {
      statusText = '⚠️ Partial outage - some nodes offline';
      statusColor = config.colors.warning;
    } else {
      statusText = '🔴 All nodes offline';
      statusColor = config.colors.error;
    }
    
    const embed = createEmbed({
      title: '🌐 YAKMESH Node Status',
      description: statusText,
      fields,
      color: statusColor,
      footer: 'Official YAKMESH nodes • Last checked',
    });
    
    await interaction.editReply({ embeds: [embed] });
  },
  
  // /docs - Documentation links
  async docs(interaction) {
    const topic = interaction.options.getString('topic');
    
    const docLinks = {
      'getting-started': { title: '🚀 Getting Started', url: `${config.links.docs}/getting-started` },
      'installation': { title: '📦 Installation', url: `${config.links.docs}/installation` },
      'configuration': { title: '⚙️ Configuration', url: `${config.links.docs}/configuration` },
      'api': { title: '📡 API Reference', url: `${config.links.docs}/api` },
      'security': { title: '🔐 Security', url: `${config.links.docs}/security` },
      'protocols': { title: '📊 Protocols', url: `${config.links.docs}/protocols` },
      'annex': { title: '🔒 Annex (Encrypted P2P)', url: `${config.links.docs}/annex` },
      'gossip': { title: '💬 Gossip Protocol', url: `${config.links.docs}/gossip` },
      'oracle': { title: '🔮 Oracle System', url: `${config.links.docs}/oracle` },
    };
    
    if (topic && docLinks[topic.toLowerCase()]) {
      const doc = docLinks[topic.toLowerCase()];
      const embed = createEmbed({
        title: doc.title,
        description: `📚 [Click here to view documentation](${doc.url})`,
        footer: 'YAKMESH™ Documentation',
      });
      await interaction.reply({ embeds: [embed] });
    } else {
      // Show all docs
      const fields = Object.entries(docLinks).map(([key, val]) => ({
        name: val.title,
        value: `\`/docs ${key}\` or [view online](${val.url})`,
        inline: true,
      }));
      
      const embed = createEmbed({
        title: '📚 YAKMESH Documentation',
        description: 'Choose a topic or visit the [full documentation](' + config.links.docs + ')',
        fields,
        footer: 'Use /docs <topic> for specific documentation',
      });
      await interaction.reply({ embeds: [embed] });
    }
  },
  
  // /changelog - Recent changes
  async changelog(interaction) {
    const embed = createEmbed({
      title: '📝 YAKMESH Changelog',
      description: `**Latest: v${config.version}**`,
      url: `${config.links.github}/blob/main/CHANGELOG.md`,
      fields: [
        {
          name: '🧪 v2.3.0 - Testing & Oracle Hardening',
          value: '• 562+ tests (Oracle, Protocol, Multi-Node, Security, Mesh)\n• Fixed ML-KEM768 cipherText capitalization\n• BYOND adapter for game server hosting\n• Oracle path normalization fix',
          inline: false,
        },
        {
          name: '🌐 v2.2.0 - YAK:// Protocol & Remote Bookmarks',
          value: '• YAK:// custom URL scheme with builtin routes\n• Remote bookmark sync via mesh gossip\n• DOKO revocation system for key compromise\n• SSL/TLS binding with certificate fingerprints',
          inline: false,
        },
        {
          name: '🔐 v2.0.0 - NAMCHE Gateway & DOKO Identity',
          value: '• 7-gate verification flow (math as authority)\n• DOKO distributed identity documents\n• iO obfuscation for all user-facing identifiers\n• Post-quantum ML-DSA-65 + ML-KEM768',
          inline: false,
        },
      ],
      footer: 'View full changelog on GitHub',
    });
    
    await interaction.reply({ embeds: [embed] });
  },
  
  // /install - Quick install guide
  async install(interaction) {
    const embed = createEmbed({
      title: '📦 Install YAKMESH',
      description: '```bash\n# Install from npm\nnpm install yakmesh\n\n# Initialize a new node\nnpx yakmesh init\n\n# Start the node\nnpx yakmesh start\n```',
      fields: [
        { name: '📋 Requirements', value: 'Node.js 18+ required', inline: true },
        { name: '📖 Full Guide', value: `[Documentation](${config.links.docs}/getting-started)`, inline: true },
      ],
      footer: 'YAKMESH™ - npm install yakmesh',
    });
    await interaction.reply({ embeds: [embed] });
  },
  
  // /ask - AI-powered Q&A
  async ask(interaction) {
    const question = interaction.options.getString('question');
    
    if (!model) {
      await interaction.reply({
        content: '❌ AI features are not configured. Please check the documentation or ask in the chat!',
        ephemeral: true,
      });
      return;
    }
    
    await interaction.deferReply();
    
    try {
      const prompt = `${YAKMESH_CONTEXT}\n\nUser question: ${question}\n\nProvide a helpful, concise answer:`;
      const result = await model.generateContent(prompt);
      const response = result.response.text();
      
      // Truncate if too long for Discord
      const truncated = response.length > 1900 
        ? response.slice(0, 1900) + '...\n\n*[Response truncated]*'
        : response;
      
      const embed = createEmbed({
        title: '🦬 YakBot Answer',
        description: truncated,
        fields: [
          { name: '❓ Question', value: question.slice(0, 200), inline: false },
        ],
        color: config.colors.info,
        footer: 'Powered by Gemini AI • Always verify with official docs',
      });
      
      await interaction.editReply({ embeds: [embed] });
    } catch (error) {
      console.error('AI error:', error);
      await interaction.editReply({
        content: '❌ Sorry, I had trouble generating a response. Please try again or check the documentation!',
      });
    }
  },
  
  // /ping - Simple ping
  async ping(interaction) {
    const latency = Date.now() - interaction.createdTimestamp;
    const embed = createEmbed({
      title: '🏓 Pong!',
      fields: [
        { name: 'Bot Latency', value: `${latency}ms`, inline: true },
        { name: 'API Latency', value: `${Math.round(client.ws.ping)}ms`, inline: true },
      ],
      color: latency < 200 ? config.colors.success : config.colors.warning,
      footer: 'YakBot Status',
    });
    await interaction.reply({ embeds: [embed] });
  },
  
  // /links - All social links
  async links(interaction) {
    const embed = createEmbed({
      title: '🔗 YAKMESH Links',
      description: 'Connect with the YAKMESH community',
      fields: [
        { name: '🌐 Website', value: `[yakmesh.dev](${config.links.website})`, inline: true },
        { name: '📖 GitHub', value: `[yakmesh/yakmesh](${config.links.github})`, inline: true },
        { name: '📦 npm', value: `[yakmesh](${config.links.npm})`, inline: true },
        { name: '📚 Docs', value: `[Documentation](${config.links.docs})`, inline: true },
        { name: '💬 Discord', value: `[Join Server](${config.links.discord})`, inline: true },
        { name: '🐦 Twitter/X', value: `[@yakmesh](${config.links.twitter})`, inline: true },
        { name: '📱 Telegram', value: `[@yakmesh](${config.links.telegram})`, inline: true },
        { name: '❤️ Patreon', value: `[Support Us](${config.links.patreon})`, inline: true },
      ],
      footer: 'YAKMESH™ - Sturdy & Secure',
    });
    await interaction.reply({ embeds: [embed] });
  },
  
  // /help - Show all commands
  async help(interaction) {
    const embed = createEmbed({
      title: '🦬 YakBot Commands',
      description: 'Here are all available commands:',
      fields: [
        { name: '📊 `/status`', value: 'Show YAKMESH version and project stats', inline: true },
        { name: '🌐 `/nodes`', value: 'Check official node health status', inline: true },
        { name: '📚 `/docs [topic]`', value: 'Get documentation links', inline: true },
        { name: '📝 `/changelog`', value: 'View recent changes', inline: true },
        { name: '📦 `/install`', value: 'Quick installation guide', inline: true },
        { name: '❓ `/ask <question>`', value: 'Ask YakBot about YAKMESH', inline: true },
        { name: '🔗 `/links`', value: 'All social and resource links', inline: true },
        { name: '❔ `/faq`', value: 'Frequently asked questions', inline: true },
        { name: '🏓 `/ping`', value: 'Check bot latency', inline: true },
        { name: '📈 `/botstats`', value: 'View bot performance metrics', inline: true },
      ],
      footer: 'YAKMESH™ - Sturdy & Secure',
    });
    await interaction.reply({ embeds: [embed] });
  },
  
  // /faq - Frequently asked questions
  async faq(interaction) {
    const embed = createEmbed({
      title: '❔ Frequently Asked Questions',
      description: 'Common questions about YAKMESH',
      fields: [
        { 
          name: '🦬 What is YAKMESH?', 
          value: 'YAKMESH (Yielding Atomic Kernel Modular Encryption Secured Hub) is a post-quantum secure P2P mesh network designed for the 2026 threat landscape.',
          inline: false,
        },
        { 
          name: '🔐 What makes it "post-quantum"?', 
          value: 'We use ML-DSA-65/87 (NIST FIPS 204) for signatures and ML-KEM-768/1024 (NIST FIPS 203) for key exchange. These algorithms are resistant to quantum computer attacks.',
          inline: false,
        },
        { 
          name: '💻 What are the requirements?', 
          value: 'Node.js 18+ is required. Install with `npm install yakmesh`.',
          inline: false,
        },
        { 
          name: '🌐 How do nodes find each other?', 
          value: 'Nodes with identical code share the same "network name" derived from the codebase hash via iO obfuscation. SHERPA DHT and gossip handle peer discovery.',
          inline: false,
        },
        { 
          name: '🔒 Is traffic encrypted?', 
          value: 'Yes! Annex provides ML-KEM768 key exchange + XChaCha20-Poly1305 encryption with perfect forward secrecy for P2P channels.',
          inline: false,
        },
        { 
          name: '🛡️ What is NAMCHE/DOKO?', 
          value: 'NAMCHE is the 7-gate verification gateway (math as authority). DOKO is the distributed identity system for nodes, users, and domains.',
          inline: false,
        },
        { 
          name: '📦 Is it production ready?', 
          value: 'YAKMESH is actively developed with 562+ tests. Check releases for stable versions. Current: v' + config.version,
          inline: false,
        },
      ],
      footer: 'More questions? Use /ask <question> or check the docs!',
    });
    await interaction.reply({ embeds: [embed] });
  },
  
  // /botstats - Bot performance metrics
  async botstats(interaction) {
    const uptime = Date.now() - stats.startTime;
    const days = Math.floor(uptime / (1000 * 60 * 60 * 24));
    const hours = Math.floor((uptime % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((uptime % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((uptime % (1000 * 60)) / 1000);
    
    const uptimeStr = days > 0 
      ? `${days}d ${hours}h ${minutes}m` 
      : hours > 0 
        ? `${hours}h ${minutes}m ${seconds}s`
        : `${minutes}m ${seconds}s`;
    
    // Memory usage
    const memUsage = process.memoryUsage();
    const memMB = (memUsage.heapUsed / 1024 / 1024).toFixed(1);
    const memTotal = (memUsage.heapTotal / 1024 / 1024).toFixed(1);
    
    // Calculate messages per hour
    const hoursUp = uptime / (1000 * 60 * 60) || 1;
    const msgsPerHour = (stats.messagesReceived / hoursUp).toFixed(1);
    
    const embed = createEmbed({
      title: '📈 YakBot Performance',
      description: 'Real-time bot statistics and metrics',
      fields: [
        { name: '⏱️ Uptime', value: uptimeStr, inline: true },
        { name: '🏓 Latency', value: `${Math.round(client.ws.ping)}ms`, inline: true },
        { name: '💾 Memory', value: `${memMB}/${memTotal} MB`, inline: true },
        { name: '📨 Messages', value: `${stats.messagesReceived}`, inline: true },
        { name: '⚡ Commands', value: `${stats.commandsProcessed}`, inline: true },
        { name: '🤖 AI Queries', value: `${stats.aiQueriesProcessed}`, inline: true },
        { name: '💬 Mentions', value: `${stats.mentionsProcessed}`, inline: true },
        { name: '📊 Msgs/Hour', value: `${msgsPerHour}`, inline: true },
        { name: '❌ Errors', value: `${stats.errors}`, inline: true },
        { name: '🖥️ Servers', value: `${client.guilds.cache.size}`, inline: true },
        { name: '👥 Users', value: `${client.guilds.cache.reduce((a, g) => a + g.memberCount, 0)}`, inline: true },
        { name: '🟢 Status', value: 'Online', inline: true },
      ],
      color: config.colors.info,
      footer: `YakBot v1.0 • Node.js ${process.version}`,
    });
    await interaction.reply({ embeds: [embed] });
  },
};

// Handle slash commands
client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isChatInputCommand()) return;
  
  const handler = commands[interaction.commandName];
  if (handler) {
    try {
      await handler(interaction);
    } catch (error) {
      console.error(`Error handling /${interaction.commandName}:`, error);
      const reply = interaction.deferred || interaction.replied
        ? interaction.editReply
        : interaction.reply;
      await reply.call(interaction, {
        content: '❌ An error occurred. Please try again.',
        ephemeral: true,
      });
    }
  }
});

// Welcome new members
client.on(Events.GuildMemberAdd, async (member) => {
  const welcomeChannel = member.guild.channels.cache.find(
    ch => ch.name === 'welcome' || ch.name === 'general'
  );
  
  if (welcomeChannel) {
    const embed = createEmbed({
      title: `🦬 Welcome to YAKMESH, ${member.user.username}!`,
      description: `Thanks for joining! Here are some quick links to get started:\n\n` +
        `📦 **Install:** \`npm install yakmesh\`\n` +
        `📚 **Docs:** ${config.links.docs}\n` +
        `💬 **Need help?** Use \`/ask <question>\` or ask in the chat!\n\n` +
        `*YAKMESH is a post-quantum secure P2P mesh network.*`,
      color: config.colors.success,
      footer: 'YAKMESH™ - Sturdy & Secure',
    });
    
    await welcomeChannel.send({ embeds: [embed] });
  }
});

// Handle @mentions and direct messages
client.on(Events.MessageCreate, async (message) => {
  // Ignore bot messages
  if (message.author.bot) return;
  
  // Check if bot was mentioned or it's a DM
  const isMentioned = message.mentions.has(client.user);
  const isDM = message.channel.type === 1; // DM channel
  
  if (!isMentioned && !isDM) return;
  
  // Get the message content without the mention
  let content = message.content
    .replace(new RegExp(`<@!?${client.user.id}>`, 'g'), '')
    .trim();
  
  // If empty after removing mention, send help
  if (!content) {
    const embed = createEmbed({
      title: '🦬 Hey there! I\'m YakBot',
      description: `I'm here to help with all things YAKMESH!\n\n` +
        `**You can:**\n` +
        `• Ask me anything: \`@YakBot how does gossip work?\`\n` +
        `• Use slash commands: \`/status\`, \`/docs\`, \`/ask\`\n` +
        `• Check node health: \`/nodes\`\n\n` +
        `Try asking me a question about YAKMESH! 🚀`,
      footer: 'YAKMESH™ - Sturdy & Secure',
    });
    await message.reply({ embeds: [embed] });
    return;
  }
  
  // Quick responses for common keywords
  const lowerContent = content.toLowerCase();
  
  // Greetings
  if (/^(hi|hello|hey|sup|yo|howdy|greetings)/i.test(lowerContent)) {
    await message.reply(`Hey ${message.author.username}! 👋 How can I help you with YAKMESH today? Feel free to ask me anything!`);
    return;
  }
  
  // Thanks
  if (/^(thanks|thank you|thx|ty)/i.test(lowerContent)) {
    await message.reply(`You're welcome! 🦬 Let me know if you need anything else!`);
    return;
  }
  
  // Install/setup questions - quick response
  if (/how.*(install|setup|start|begin|get started)/i.test(lowerContent)) {
    const embed = createEmbed({
      title: '📦 Quick Install Guide',
      description: '```bash\n# Install YAKMESH\nnpm install yakmesh\n\n# Initialize a node\nnpx yakmesh init\n\n# Start your node\nnpx yakmesh start\n```',
      fields: [
        { name: '📋 Requirements', value: 'Node.js 18+', inline: true },
        { name: '📚 Full Docs', value: `[Getting Started](${config.links.docs}/getting-started)`, inline: true },
      ],
      footer: 'YAKMESH™ - npm install yakmesh',
    });
    await message.reply({ embeds: [embed] });
    return;
  }
  
  // Version/status questions
  if (/what.*(version|latest)/i.test(lowerContent) || lowerContent === 'version') {
    const npm = await getNpmStats();
    await message.reply(`📦 The latest YAKMESH version is **v${npm.version}**\n\nInstall with: \`npm install yakmesh\``);
    return;
  }
  
  // If AI is available, use it for complex questions
  if (model) {
    try {
      await message.channel.sendTyping();
      
      const prompt = `${YAKMESH_CONTEXT}\n\nUser message: ${content}\n\nProvide a helpful, friendly, and concise response. Keep it under 1500 characters. Use Discord markdown formatting.`;
      const result = await model.generateContent(prompt);
      const response = result.response.text();
      
      // Truncate if needed
      const truncated = response.length > 1900 
        ? response.slice(0, 1900) + '...'
        : response;
      
      await message.reply(truncated);
    } catch (error) {
      console.error('AI chat error:', error);
      await message.reply(`🤔 I had trouble understanding that. Try using \`/ask ${content.slice(0, 50)}\` or rephrase your question!`);
    }
  } else {
    // No AI, give helpful response
    await message.reply(
      `I'm not sure about that specific question. Here are some things I can help with:\n\n` +
      `• \`/status\` - Check YAKMESH project status\n` +
      `• \`/docs\` - Get documentation links\n` +
      `• \`/nodes\` - Check node health\n` +
      `• \`/install\` - Installation guide\n\n` +
      `Or check the docs: ${config.links.docs}`
    );
  }
});

// Ready event
client.once(Events.ClientReady, (c) => {
  log.info('YakBot is online', {
    user: c.user.tag,
    servers: c.guilds.cache.size,
    ai: model ? 'Gemini enabled' : 'Not configured',
    chat: 'Mentions & DMs enabled'
  });
  
  // Set activity
  client.user.setActivity('YAKMESH™ | @me or /help', { type: 3 }); // Watching
});

// Login
if (!config.token) {
  log.error('DISCORD_TOKEN environment variable not set');
  log.info('To run YakBot: 1. Create a bot at discord.com/developers 2. Get token 3. Run with DISCORD_TOKEN=xxx');
  process.exit(1);
}

client.login(config.token);
