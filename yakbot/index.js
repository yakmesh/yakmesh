/**
 * YakBot - YAKMESH™ Discord Community Bot
 * 
 * Features:
 * - /status - Show current version, links
 * - /docs [topic] - Quick documentation links
 * - /changelog - Recent changes
 * - /ask [question] - AI-powered Q&A about YAKMESH
 * - /nodes - Check health of official YAKMESH nodes
 * - /ping - Bot latency check
 * - Auto-greet new members
 * 
 * @copyright 2026 YAKMESH™ Contributors
 */

import { Client, GatewayIntentBits, EmbedBuilder, Events } from 'discord.js';
import { GoogleGenerativeAI } from '@google/generative-ai';
import 'dotenv/config';

// Configuration
const config = {
  // Discord bot token (from Discord Developer Portal)
  token: process.env.DISCORD_TOKEN,
  
  // Gemini API key for AI responses
  geminiKey: process.env.GEMINI_API_KEY,
  
  // Current version
  version: '1.4.0',
  
  // Official YAKMESH nodes for health checks
  officialNodes: [
    { name: 'Alpha (Primary)', url: 'https://alpha.yakmesh.dev', icon: '🅰️' },
    { name: 'Beta (Backup)', url: 'https://beta.yakmesh.dev', icon: '🅱️' },
    { name: 'PeerQuanta', url: 'https://peerquanta.com/yakmesh', icon: '🌐' },
  ],
  
  // Links
  links: {
    github: 'https://github.com/yakmesh/yakmesh',
    npm: 'https://npmjs.com/package/yakmesh',
    docs: 'https://yakmesh.dev/docs',
    website: 'https://yakmesh.dev',
    discord: 'https://discord.gg/E62tAE2wGh',
    twitter: 'https://x.com/yakmesh',
    telegram: 'https://t.me/yakmesh',
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
You are YakBot, the helpful assistant for YAKMESH™ - a post-quantum secure P2P mesh network.

Key facts about YAKMESH:
- YAKMESH stands for: Yielding Atomic Kernel Modular Encryption Secured Hub
- Current version: ${config.version}
- Written in Node.js/JavaScript
- Uses ML-DSA-65 (NIST FIPS 204) for post-quantum signatures
- Uses ML-KEM768 (Kyber) for quantum-resistant key exchange
- Self-verifying oracle for deterministic validation
- Content-addressed storage with SHA3-256 hashing
- Gossip protocol for message propagation
- WebSocket-based mesh networking

Protocol Stack (top to bottom):
1. HTTP API - Public content delivery (CDN layer)
2. Annex - Encrypted point-to-point messaging (ML-KEM768 + AES-256-GCM)
3. Gossip - Epidemic-style message propagation
4. Beacon - Emergency broadcast with priority levels
5. Phantom - Onion routing for anonymity
6. Mesh - Core P2P network with Code Proof Protocol

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
  ],
});

// Initialize Gemini AI
let genAI = null;
let model = null;

if (config.geminiKey) {
  genAI = new GoogleGenerativeAI(config.geminiKey);
  model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });
  console.log('✓ Gemini AI initialized');
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
    
    // Try the /health or /status endpoint first, fallback to root
    let response;
    try {
      response = await fetch(`${nodeUrl}/health`, { 
        signal: controller.signal,
        headers: { 'Accept': 'application/json' }
      });
    } catch {
      response = await fetch(nodeUrl, { signal: controller.signal });
    }
    
    clearTimeout(timeout);
    const latency = Date.now() - start;
    
    if (response.ok) {
      // Try to get version info if available
      let version = null;
      let peers = null;
      let content = null;
      
      try {
        const data = await response.json();
        version = data.version;
        peers = data.peers || data.peerCount;
        content = data.content || data.contentCount;
      } catch {
        // Not JSON, that's OK
      }
      
      return {
        online: true,
        latency,
        version,
        peers,
        content,
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
      
      if (node.version) value += `📦 Version: \`${node.version}\`\n`;
      if (node.peers !== null && node.peers !== undefined) value += `👥 Peers: ${node.peers}\n`;
      if (node.content !== null && node.content !== undefined) value += `📄 Content: ${node.content}\n`;
      if (!node.online && node.error) value += `❌ Error: ${node.error}\n`;
      
      value += `🔗 [Visit](${node.url})`;
      
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
          name: '🔐 v1.4.0 - Annex Encrypted P2P',
          value: '• Added Yakmesh Annex - encrypted point-to-point messaging\n• ML-KEM768 (Kyber) quantum-resistant key exchange\n• Perfect forward secrecy\n• Trademark cleanup',
          inline: false,
        },
        {
          name: '🐛 v1.3.2 - Bug Fixes',
          value: '• Fixed gossip propagation for content distribution\n• Multi-node content sync improvements',
          inline: false,
        },
        {
          name: '🌐 v1.3.1 - Public Content Delivery',
          value: '• Content-addressed storage API\n• First successful LAN mesh peering\n• Social channels launched',
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
        { name: '🏓 `/ping`', value: 'Check bot latency', inline: true },
      ],
      footer: 'YAKMESH™ - Sturdy & Secure',
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
  console.log(`\n🦬 YakBot is online!`);
  console.log(`   Logged in as: ${c.user.tag}`);
  console.log(`   Servers: ${c.guilds.cache.size}`);
  console.log(`   AI: ${model ? '✓ Gemini enabled' : '✗ Not configured'}`);
  console.log(`   Chat: ✓ Mentions & DMs enabled\n`);
  
  // Set activity
  client.user.setActivity('YAKMESH™ | @me or /help', { type: 3 }); // Watching
});

// Login
if (!config.token) {
  console.error('❌ DISCORD_TOKEN environment variable not set!');
  console.log('\nTo run YakBot:');
  console.log('1. Create a bot at https://discord.com/developers/applications');
  console.log('2. Get your bot token');
  console.log('3. Run: DISCORD_TOKEN=your_token GEMINI_API_KEY=your_key node index.js\n');
  process.exit(1);
}

client.login(config.token);
