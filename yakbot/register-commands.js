/**
 * Register YakBot slash commands with Discord
 * 
 * Run this once to register commands:
 * node register-commands.js
 */

import { REST, Routes, SlashCommandBuilder } from 'discord.js';
import 'dotenv/config';

const commands = [
  new SlashCommandBuilder()
    .setName('status')
    .setDescription('Show YAKMESH current version and stats'),
    
  new SlashCommandBuilder()
    .setName('nodes')
    .setDescription('Check health status of official YAKMESH nodes'),
    
  new SlashCommandBuilder()
    .setName('docs')
    .setDescription('Get documentation links')
    .addStringOption(option =>
      option.setName('topic')
        .setDescription('Documentation topic')
        .setRequired(false)
        .addChoices(
          { name: '🚀 Getting Started', value: 'getting-started' },
          { name: '📦 Installation', value: 'installation' },
          { name: '⚙️ Configuration', value: 'configuration' },
          { name: '📡 API Reference', value: 'api' },
          { name: '🔐 Security', value: 'security' },
          { name: '📊 Protocols', value: 'protocols' },
          { name: '🔒 Annex (Encrypted P2P)', value: 'annex' },
          { name: '💬 Gossip Protocol', value: 'gossip' },
          { name: '🔮 Oracle System', value: 'oracle' },
        )),
        
  new SlashCommandBuilder()
    .setName('changelog')
    .setDescription('Show recent YAKMESH changes'),
    
  new SlashCommandBuilder()
    .setName('install')
    .setDescription('Get quick installation instructions'),
    
  new SlashCommandBuilder()
    .setName('ask')
    .setDescription('Ask YakBot a question about YAKMESH')
    .addStringOption(option =>
      option.setName('question')
        .setDescription('Your question about YAKMESH')
        .setRequired(true)),
        
  new SlashCommandBuilder()
    .setName('ping')
    .setDescription('Check bot latency'),
    
  new SlashCommandBuilder()
    .setName('links')
    .setDescription('Get all YAKMESH social and resource links'),
    
  new SlashCommandBuilder()
    .setName('help')
    .setDescription('Show all available YakBot commands'),
    
  new SlashCommandBuilder()
    .setName('botstats')
    .setDescription('View YakBot performance metrics and statistics'),
];

const token = process.env.DISCORD_TOKEN;
const clientId = process.env.DISCORD_CLIENT_ID;

if (!token || !clientId) {
  console.error('❌ Missing environment variables!');
  console.log('\nUsage:');
  console.log('DISCORD_TOKEN=xxx DISCORD_CLIENT_ID=xxx node register-commands.js\n');
  process.exit(1);
}

const rest = new REST().setToken(token);

(async () => {
  try {
    console.log('🔄 Registering slash commands...');
    
    // Register globally (takes up to 1 hour to propagate)
    await rest.put(
      Routes.applicationCommands(clientId),
      { body: commands.map(cmd => cmd.toJSON()) },
    );
    
    console.log('✅ Successfully registered commands:');
    commands.forEach(cmd => console.log(`   /${cmd.name}`));
    console.log('\n📝 Note: Global commands may take up to 1 hour to appear.');
    console.log('   For instant testing, use guild-specific commands.\n');
  } catch (error) {
    console.error('❌ Error registering commands:', error);
  }
})();
