# Yakmesh DMAPI

DreamMaker API library for integrating BYOND games with Yakmesh mesh network.

## Installation

1. Copy the `dmapi/` folder to your BYOND project root
2. Edit `yakmesh_config.dm` with your settings
3. Add to your `.dme` file:
   ```dm
   #include "dmapi/yakmesh_config.dm"
   #include "dmapi/yakmesh.dm"
   ```

4. Initialize in `world/New()`:
   ```dm
   /world/New()
       ..()
       YakmeshInit()
   ```

5. Add Topic handler:
   ```dm
   /world/Topic(T, Addr, Master, Keys)
       var/yakmesh_result = YakmeshHandleTopic(T, Addr)
       if(yakmesh_result)
           return yakmesh_result
       return ..()
   ```

## Configuration

Edit `yakmesh_config.dm`:

```dm
#define YAKMESH_BRIDGE_URL "http://127.0.0.1:8080"  // Your Yakmesh node
#define YAKMESH_GAME_ID "pondera"                   // Your game ID
#define YAKMESH_SERVER_NAME "My Pondera Server"     // Display name
#define YAKMESH_MAX_PLAYERS 50                      // Max players
#define YAKMESH_DEBUG 1                             // Enable logging
#define YAKMESH_AUTO_REGISTER 1                     // Auto-register on start
#define YAKMESH_AUTO_SAVE_INTERVAL 0                // Auto-save (0=off)
```

## Usage

### Server Discovery

```dm
// Get all servers running your game
var/list/servers = YakmeshDiscoverServers(YAKMESH_GAME_ID)
for(var/list/server in servers)
    world << "[server["name"]]: [server["players"]]/[server["maxPlayers"]]"

// Get all online servers
var/list/all = YakmeshDiscoverServers()
```

### World Persistence

```dm
// Save world state
var/cid = YakmeshSaveWorld()
if(cid)
    world << "World saved! ID: [cid]"

// Load world state
if(YakmeshLoadWorld(cid))
    world << "World restored!"

// Mark atoms for persistence
/obj/machine
    yakmesh_persist = TRUE
    
    YakmeshSerialize()
        return list(
            "powered" = src.powered,
            "health" = src.health
        )
    
    YakmeshDeserialize(list/data)
        src.powered = data["powered"]
        src.health = data["health"]
```

### Player DOKO Identities

```dm
/client/New()
    ..()
    
    // Check if player has a DOKO
    var/doko = YakmeshGetPlayerDoko(src.ckey)
    if(doko)
        src << "Welcome back! DOKO: [doko["dokoId"]]"
    else
        src << "Create a Yakmesh identity with !doko"

// Create DOKO command
/client/verb/doko_create()
    var/result = YakmeshCreatePlayerDoko(src.ckey, list(
        "favorite_role" = "scientist"
    ))
    if(result && result["success"])
        src << "DOKO created!"
        src << "IMPORTANT: Save your secret key: [result["secretKey"]]"
    else
        src << "Failed to create DOKO"
```

### Handling Topic Requests

The DMAPI automatically handles these Topics:

- `yakmesh=status` - Returns server status
- `yakmesh=ping` - Returns "pong"  
- `yakmesh=player_count` - Returns player count
- `yakmesh=save` - Triggers world save
- `yakmesh=challenge&data=X` - Signs challenge for verification

Custom Topics:

```dm
/world/Topic(T, Addr, Master, Keys)
    // Let Yakmesh handle its topics first
    var/result = YakmeshHandleTopic(T, Addr)
    if(result)
        return result
    
    // Your custom topics
    var/list/params = params2list(T)
    if(params["myaction"])
        return HandleMyAction(params)
    
    return ..()
```

## API Reference

### Initialization
- `YakmeshInit()` - Initialize the DMAPI (call in world/New)

### Server
- `YakmeshRegisterServer()` - Register with mesh
- `YakmeshDiscoverServers(gameId)` - Find other servers

### Persistence  
- `YakmeshSaveWorld(metadata)` - Save world state, returns CID
- `YakmeshLoadWorld(cid)` - Load world state, returns TRUE/FALSE
- `YakmeshGetWorldState()` - Override for custom serialization
- `YakmeshApplyWorldState(data)` - Override for custom loading

### Player Identity
- `YakmeshGetPlayerDoko(ckey)` - Get player's DOKO info
- `YakmeshCreatePlayerDoko(ckey, claims)` - Create new DOKO
- `YakmeshVerifyPlayerDoko(ckey, challenge, signature)` - Verify signature

### Topic Handling
- `YakmeshHandleTopic(T, Addr)` - Handle Yakmesh topics

### Serialization Hooks
- `/atom/var/yakmesh_persist` - Set TRUE to include in saves
- `/atom/proc/YakmeshSerialize()` - Override to customize save data
- `/atom/proc/YakmeshDeserialize(data)` - Override to restore data

## Requirements

- BYOND 514+
- Yakmesh node running with HTTP bridge enabled
- Network access to bridge URL

## Example Integration

See `examples/pondera_integration.dm` for a complete example.

## License

MIT
