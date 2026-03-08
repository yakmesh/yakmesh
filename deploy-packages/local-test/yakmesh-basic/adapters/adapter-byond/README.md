# Yakmesh BYOND Adapter

Bridges BYOND game servers (DreamDaemon) with the Yakmesh mesh network. Enables games like SS13, Pondera, and other BYOND titles to benefit from mesh networking features.

## Features

- **Server Discovery**: Automatically discover other BYOND servers on the mesh via SHERPA beacons
- **Status Broadcasting**: Broadcast player count, map, and server status across the mesh
- **Topic Protocol**: Full implementation of the BYOND Topic wire protocol
- **Topic Relay**: Send Topic messages to remote servers through the mesh
- **World Persistence**: Save/load world states to the mesh content store
- **Player Identities**: DOKO identities for cross-server player reputation
- **Server Verification**: NAMCHE-style multi-gate verification for trust

## Installation

```bash
# From yakmesh-node directory
npm install

# Or add to your project
npm install @yakmesh/adapter-byond
```

## Quick Start

### Basic Usage

```javascript
import BYONDAdapter from '@yakmesh/adapter-byond';

// Create adapter with your Yakmesh node
const adapter = new BYONDAdapter(yakmeshNode, {
  statusInterval: 30000,   // Poll servers every 30s
  broadcastInterval: 60000, // Broadcast to mesh every 60s
});

// Initialize
await adapter.init();

// Register your game server
const server = await adapter.registerServer({
  gameId: 'pondera',
  host: 'localhost',
  port: 6666,
  name: 'My Pondera Server',
  maxPlayers: 50,
  tags: ['roleplay', 'development'],
});

console.log(`Server registered: ${server.id}`);
```

### Discover Other Servers

```javascript
// Get all online Pondera servers
const ponderaServers = adapter.findByGame('pondera');

for (const server of ponderaServers) {
  console.log(`${server.name}: ${server.players}/${server.maxPlayers} players`);
}

// Get all servers matching a filter
const servers = adapter.getServers({
  status: 'online',
  tag: 'roleplay',
});
```

### Send Topic Messages

```javascript
// Send to local server
const response = await adapter.sendTopic(serverId, 'status');
console.log('Players:', response.parsed.players);

// Send custom topic
const result = await adapter.sendTopic(serverId, 'action=restart&key=secret123');
```

### World Persistence

```javascript
// Save world state
const worldData = await fetchWorldDataFromGame();
const { cid, hash } = await adapter.saveWorld(serverId, worldData, {
  reason: 'scheduled_backup',
  round: 42,
});

console.log(`World saved: ${cid}`);

// Load world state
const savedWorld = await adapter.loadWorld(cid);
await restoreWorldToGame(savedWorld);
```

## Topic Protocol

The adapter implements the BYOND Topic wire protocol for direct communication with DreamDaemon servers.

### Standalone Topic Client

```javascript
import { BYONDTopicClient, createTopicConnection } from '@yakmesh/adapter-byond/topic-client';

// One-off query
const client = new BYONDTopicClient({ timeout: 5000, retries: 2 });
const response = await client.queryStatus('localhost', 6666);

// Persistent connection
const conn = createTopicConnection({
  host: 'localhost',
  port: 6666,
});

await conn.ping();
const status = await conn.status();
await conn.send('custom_topic=value');
```

### Protocol Format

The BYOND Topic protocol uses a simple binary format:

```
Request:  [0x00][0x83][size_hi][size_lo][0x00][0x6A][topic...][0x00]
Response: [0x00][0x83][size_hi][size_lo][type][data...]

Response Types:
  0x00 = null
  0x06 = string (null-terminated)
  0x2a = float (4 bytes, little-endian)
```

## Security Integration

### Player DOKO Identities

Link BYOND ckeys to self-sovereign DOKO identities:

```javascript
import BYONDSecurity from '@yakmesh/adapter-byond/security';

const security = new BYONDSecurity(adapter);

// Create identity for player
const result = security.createPlayerDoko('SomeCkey123', {
  claims: { favoriteRole: 'botanist' },
});

if (result.success) {
  console.log(`DOKO created: ${result.dokoId}`);
  // IMPORTANT: Give secretKey to player ONCE
}

// Verify player identity
const doko = security.getPlayerDoko('SomeCkey123');
if (doko) {
  console.log(`Player has DOKO: ${doko.dokoId}`);
}
```

### Server Verification

Verify servers through multi-gate verification:

```javascript
const verification = await security.verifyServer(serverId);

console.log(`Verified: ${verification.verified}`);
console.log(`Gates passed: ${verification.passedGates}/${verification.totalGates}`);
```

Gates:
1. **Topic Reachable**: Server responds to ping
2. **Version Match**: Reported version matches claim
3. **Challenge Response**: Server responds to signed challenge
4. **Hub Registration**: Server is on BYOND hub (if claimed)
5. **Mesh Consensus**: Multiple nodes confirm server

### Trust-Based Features

Control feature access based on trust level:

```javascript
if (security.canUseFeature(serverId, 'TOPIC_RELAY')) {
  await adapter.sendTopic(serverId, 'command');
}
```

Trust thresholds:
- `SERVER_DISCOVERY`, `TOPIC_QUERY` - STRANGER (anyone)
- `WORLD_PERSISTENCE`, `TOPIC_RELAY` - ACQUAINTANCE
- `SERVER_TO_SERVER_MESSAGING` - FRIEND
- `MESH_VERIFICATION_VOTE` - TRUSTED_PARTNER

## Game Integration (DM Code)

### Basic Topic Handler

```dm
/world/Topic(T, Addr, Master, Keys)
    if(T == "status")
        return "players=[clients.len]&map=[map_name]&version=[version]"
    
    if(T == "ping")
        return "pong"
    
    // Yakmesh-specific topics
    if(copytext(T, 1, 8) == "yakmesh")
        return handle_yakmesh_topic(T, Addr)
    
    return ..()

/proc/handle_yakmesh_topic(T, Addr)
    var/list/params = params2list(T)
    
    switch(params["action"])
        if("save_world")
            return export_world_state()
        if("player_count")
            return "[clients.len]"
        if("verify")
            return sign_challenge(params["challenge"])
    
    return "unknown"
```

### World Persistence

```dm
/proc/export_world_state()
    var/savefile/F = new()
    F["version"] = SAVE_VERSION
    F["round_id"] = round_id
    F["objects"] << get_persistent_objects()
    return F.ExportText()

/proc/import_world_state(data)
    var/savefile/F = new()
    F.ImportText("", data)
    
    var/version
    F["version"] >> version
    if(version != SAVE_VERSION)
        return FALSE
    
    var/list/objects
    F["objects"] >> objects
    restore_objects(objects)
    return TRUE
```

## Events

The adapter emits events you can listen to:

```javascript
adapter.on('server-registered', (server) => {
  console.log(`Registered: ${server.name}`);
});

adapter.on('server-discovered', (server) => {
  console.log(`Discovered: ${server.name} from mesh`);
});

adapter.on('server-status', (server) => {
  console.log(`${server.name}: ${server.players} players`);
});

adapter.on('world-saved', ({ serverId, cid, hash }) => {
  console.log(`World saved: ${cid}`);
});
```

## Configuration

```javascript
const adapter = new BYONDAdapter(node, {
  // How often to poll local servers for status (ms)
  statusInterval: 30000,
  
  // How often to broadcast server list to mesh (ms)
  broadcastInterval: 60000,
  
  // Port for Topic relay server (0 = disabled)
  relayPort: 0,
  
  // Enable world persistence features
  enablePersistence: true,
  
  // Enable player DOKO identities
  enablePlayerDoko: true,
});
```

## Testing

```bash
# Run BYOND adapter tests
npm run test:byond

# Run all tests including BYOND
npm run test:all
```

## Examples

See `examples/pondera-hosting.js` for a complete example:

```bash
node adapters/adapter-byond/examples/pondera-hosting.js
```

## Requirements

- Node.js >= 18.0.0
- Yakmesh node v2.3.0+
- BYOND server (DreamDaemon) for actual game hosting

## License

MIT

## Author

AERProductions - Pondera Development Team
