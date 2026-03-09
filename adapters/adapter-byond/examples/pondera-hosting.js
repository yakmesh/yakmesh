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
 * BYOND Adapter Usage Examples
 * 
 * Demonstrates how to use the Yakmesh BYOND adapter for game server hosting.
 * This example shows Pondera integration but works for any BYOND game.
 * 
 * @example
 * ```bash
 * # Start your BYOND game server normally
 * DreamDaemon pondera.dmb 7777 -trusted
 * 
 * # Then register it with Yakmesh
 * node examples/pondera-hosting.js
 * ```
 */

import BYONDAdapter, { 
  BYONDServer, 
  BYOND_TOPICS,
  SERVER_STATUS 
} from '../index.js';
import BYONDSecurity from '../security.js';

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE 1: Basic Server Registration
// ═══════════════════════════════════════════════════════════════════════════════

async function basicServerRegistration() {
  console.log('\n📡 Example 1: Basic Server Registration\n');
  
  // In real usage, you'd get this from your Yakmesh node
  const mockYakmeshNode = {
    nodeId: 'pondera-host-001',
    mesh: { on: () => {}, off: () => {} },
    gossip: { 
      spreadRumor: (topic, data) => {
        console.log(`  [GOSSIP] ${topic}:`, JSON.stringify(data).slice(0, 80) + '...');
      }
    },
    content: {
      store: async (data, meta) => `cid-${Date.now()}`,
      retrieve: async (cid) => Buffer.from('world-data'),
    },
  };

  // Create the adapter
  const adapter = new BYONDAdapter(mockYakmeshNode, {
    statusInterval: 30000,   // Poll every 30s
    broadcastInterval: 60000, // Broadcast every 60s
  });

  // Note: In real usage, call adapter.init() here
  // await adapter.init();

  // Register your Pondera server
  console.log('Registering Pondera server...');
  const server = new BYONDServer({
    gameId: 'pondera',
    host: 'localhost',
    port: 7777,
    name: 'AER Pondera Server',
    description: 'Official Pondera development server',
    version: '1.0.0',
    maxPlayers: 50,
    tags: ['development', 'roleplay', 'pondera'],
    metadata: {
      discord: 'https://discord.gg/pondera',
      website: 'https://pondera.game',
    },
  });

  console.log(`  Created server: ${server.name} (${server.id})`);
  console.log(`  Game: ${server.gameId}`);
  console.log(`  Address: ${server.host}:${server.port}`);
  console.log(`  Status: ${server.status}`);
  
  return server;
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE 2: Querying Server Status
// ═══════════════════════════════════════════════════════════════════════════════

async function queryServerStatus() {
  console.log('\n📊 Example 2: Querying Server Status\n');
  
  const { BYONDTopicClient, createTopicConnection } = await import('../topic-client.js');
  
  // Option A: One-off query
  const client = new BYONDTopicClient({ timeout: 5000 });
  
  console.log('Querying localhost:6666...');
  try {
    const status = await client.queryStatus('localhost', 6666);
    console.log('  Status:', status);
  } catch (err) {
    console.log('  Server not responding (expected if no server running)');
  }
  
  // Option B: Persistent connection for repeated queries
  console.log('\nCreating persistent connection...');
  const conn = createTopicConnection({
    host: 'localhost',
    port: 6666,
    timeout: 3000,
    retries: 2,
  });
  
  console.log('  Connection object created with methods:');
  console.log('    - conn.send(topic)');
  console.log('    - conn.status()');
  console.log('    - conn.ping()');
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE 3: Discovering Other Servers
// ═══════════════════════════════════════════════════════════════════════════════

async function discoverServers() {
  console.log('\n🔍 Example 3: Discovering Servers\n');
  
  // Simulated discovered servers from mesh
  const discoveredServers = [
    BYONDServer.fromJSON({
      id: 'remote-pondera-1',
      gameId: 'pondera',
      host: '192.168.1.100',
      port: 6666,
      name: 'Community Pondera',
      status: 'online',
      players: 15,
      maxPlayers: 50,
      map: 'station_1',
      verified: true,
    }),
    BYONDServer.fromJSON({
      id: 'remote-ss13-1',
      gameId: 'ss13',
      host: '10.0.0.5',
      port: 7777,
      name: 'TG Station',
      status: 'online',
      players: 45,
      maxPlayers: 100,
      map: 'boxstation',
      verified: true,
    }),
    BYONDServer.fromJSON({
      id: 'remote-pondera-2',
      gameId: 'pondera',
      host: '192.168.1.200',
      port: 6666,
      name: 'Test Pondera',
      status: 'offline',
      players: 0,
      verified: false,
    }),
  ];

  console.log('Servers discovered via mesh:\n');
  
  for (const server of discoveredServers) {
    const statusEmoji = server.status === 'online' ? '🟢' : '🔴';
    const verifiedEmoji = server.verified ? '✓' : '?';
    
    console.log(`  ${statusEmoji} ${server.name} [${verifiedEmoji}]`);
    console.log(`     Game: ${server.gameId} | Players: ${server.players}/${server.maxPlayers}`);
    console.log(`     Address: ${server.host}:${server.port}`);
    console.log('');
  }

  // Filter by game
  const ponderaServers = discoveredServers.filter(s => s.gameId === 'pondera');
  console.log(`Found ${ponderaServers.length} Pondera servers`);
  
  // Filter by status
  const onlineServers = discoveredServers.filter(s => s.status === 'online');
  console.log(`Found ${onlineServers.length} online servers`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE 4: World Persistence
// ═══════════════════════════════════════════════════════════════════════════════

async function worldPersistence() {
  console.log('\n💾 Example 4: World Persistence\n');
  
  console.log('World persistence allows you to:');
  console.log('  1. Save world state to the Yakmesh content store');
  console.log('  2. Replicate saves across mesh nodes');
  console.log('  3. Restore from any node if primary fails');
  console.log('');
  
  console.log('Usage in your game code (DM):');
  console.log('');
  console.log(`  // In world/Topic()
  world/Topic(T, Addr, Master, Keys)
    if(T == "yakmesh_save")
      var/savefile/F = new("world.sav")
      F << world
      // Return save data via HTTP
      return F.ExportText()
    
    if(T == "yakmesh_load")
      var/cid = text2path(T)
      // Request load from Yakmesh
      world.Export("http://localhost:8080/byond/load?cid=[cid]")
      return "loading"`);
  
  console.log('');
  console.log('The adapter handles:');
  console.log('  - Content hashing for deduplication');
  console.log('  - Mesh-wide replication');
  console.log('  - Automatic backup scheduling');
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE 5: Player DOKO Identities
// ═══════════════════════════════════════════════════════════════════════════════

async function playerDoko() {
  console.log('\n🪪 Example 5: Player DOKO Identities\n');
  
  console.log('DOKO (Decentralized Origin Key Ownership) provides:');
  console.log('  - Self-sovereign player identities');
  console.log('  - Cross-server reputation');
  console.log('  - Cryptographic authentication');
  console.log('');
  
  console.log('Flow:');
  console.log('  1. Player connects with BYOND ckey');
  console.log('  2. Game checks if ckey has a DOKO');
  console.log('  3. If not, offer to create one');
  console.log('  4. Player signs challenge to prove identity');
  console.log('  5. Server verifies and grants access');
  console.log('');
  
  console.log('Example DM integration:');
  console.log('');
  console.log(`  /client/New()
    . = ..()
    // Query Yakmesh for player's DOKO
    var/result = world.Export("http://localhost:8080/byond/doko?ckey=[ckey]")
    if(result)
      src.has_doko = TRUE
      src.trust_level = result["trust"]
    else
      // Prompt to create DOKO
      src << "Create a Yakmesh identity? Use !doko create"`);
}

// ═══════════════════════════════════════════════════════════════════════════════
// RUN EXAMPLES
// ═══════════════════════════════════════════════════════════════════════════════

async function runExamples() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  Yakmesh BYOND Adapter - Usage Examples');
  console.log('  For Pondera and other BYOND games');
  console.log('═══════════════════════════════════════════════════════════════');
  
  await basicServerRegistration();
  await queryServerStatus();
  await discoverServers();
  await worldPersistence();
  await playerDoko();
  
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('  For more information, see:');
  console.log('  - adapters/adapter-byond/README.md');
  console.log('  - https://yakmesh.dev/docs/byond');
  console.log('═══════════════════════════════════════════════════════════════\n');
}

// Run if called directly
runExamples().catch(console.error);
