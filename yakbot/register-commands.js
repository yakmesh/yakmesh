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
 * Register YakBot slash commands with Discord
 * 
 * Run this once to register commands:
 * node register-commands.js
 */

import { REST, Routes, SlashCommandBuilder } from 'discord.js';
import 'dotenv/config';
import { createLogger } from './utils/logger.js';

const log = createLogger('yakbot:register');

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
    .setName('faq')
    .setDescription('Frequently asked questions about YAKMESH'),

  new SlashCommandBuilder()
    .setName('timesync')
    .setDescription('View live AGUWA Kuramoto time-sync telemetry from the mesh'),

  new SlashCommandBuilder()
    .setName('botstats')
    .setDescription('View YakBot performance metrics and statistics'),
];

const token = process.env.DISCORD_TOKEN;
const clientId = process.env.DISCORD_CLIENT_ID;

if (!token || !clientId) {
  log.error('Missing environment variables');
  log.info('Usage: DISCORD_TOKEN=xxx DISCORD_CLIENT_ID=xxx node register-commands.js');
  process.exit(1);
}

const rest = new REST().setToken(token);

(async () => {
  try {
    log.info('Registering slash commands...');

    // Register globally (takes up to 1 hour to propagate)
    await rest.put(
      Routes.applicationCommands(clientId),
      { body: commands.map(cmd => cmd.toJSON()) },
    );

    log.info('Successfully registered commands', { commands: commands.map(cmd => cmd.name) });
    log.info('Global commands may take up to 1 hour to appear. For instant testing, use guild-specific commands.');
  } catch (error) {
    log.error('Error registering commands', { error: error.message });
  }
})();
