// ═══════════════════════════════════════════════════════════════════════════════
// YAKMESH DMAPI - DreamMaker API for Yakmesh Integration
// ═══════════════════════════════════════════════════════════════════════════════
// 
// Include this file in your BYOND project to integrate with Yakmesh mesh network.
// 
// INSTALLATION:
//   1. Copy the 'yakmesh' folder to your project
//   2. Add to your .dme: #include "yakmesh/yakmesh.dm"
//   3. Configure YAKMESH_BRIDGE_URL to point to your Yakmesh node
//   4. Call YakmeshInit() in world/New()
// 
// FEATURES:
//   - Server registration and discovery
//   - World state persistence
//   - Player DOKO identities
//   - Cross-server messaging
// 
// @version 1.0.0
// @author AERProductions
// @license MIT
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION - Modify these for your setup
// ═══════════════════════════════════════════════════════════════════════════════

/// URL of the Yakmesh HTTP bridge (default: localhost:8080)
#define YAKMESH_BRIDGE_URL "http://127.0.0.1:8080"

/// Your game's unique identifier (e.g., "pondera", "ss13-myserver")
#define YAKMESH_GAME_ID "mygame"

/// Your server's display name
#define YAKMESH_SERVER_NAME "My Game Server"

/// Maximum players (used for discovery)
#define YAKMESH_MAX_PLAYERS 50

/// API key (optional, for secured bridges)
#define YAKMESH_API_KEY null

/// Enable debug logging
#define YAKMESH_DEBUG 0

/// Auto-register on startup
#define YAKMESH_AUTO_REGISTER 1

/// Auto-save interval (in deciseconds, 0 = disabled)
#define YAKMESH_AUTO_SAVE_INTERVAL 0


// ═══════════════════════════════════════════════════════════════════════════════
// GLOBAL STATE
// ═══════════════════════════════════════════════════════════════════════════════

var/global/yakmesh_initialized = FALSE
var/global/yakmesh_server_id = null
var/global/yakmesh_last_save_cid = null
var/global/list/yakmesh_player_dokos = list()


// ═══════════════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Initialize Yakmesh integration
 * Call this in world/New() after your game is set up
 */
/proc/YakmeshInit()
	if(yakmesh_initialized)
		return TRUE
	
	YakmeshLog("Initializing Yakmesh DMAPI...")
	
	// Check bridge connectivity
	var/status = YakmeshRequest("/status", "GET")
	if(!status)
		YakmeshLog("ERROR: Cannot connect to Yakmesh bridge at [YAKMESH_BRIDGE_URL]")
		return FALSE
	
	YakmeshLog("Connected to Yakmesh bridge")
	
	// Auto-register if enabled
	#if YAKMESH_AUTO_REGISTER
	if(!YakmeshRegisterServer())
		YakmeshLog("WARNING: Server registration failed")
	#endif
	
	// Start auto-save if enabled
	#if YAKMESH_AUTO_SAVE_INTERVAL > 0
	spawn(YAKMESH_AUTO_SAVE_INTERVAL)
		YakmeshAutoSaveLoop()
	#endif
	
	yakmesh_initialized = TRUE
	YakmeshLog("Yakmesh DMAPI initialized successfully")
	return TRUE


// ═══════════════════════════════════════════════════════════════════════════════
// SERVER REGISTRATION
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Register this server with the Yakmesh mesh
 */
/proc/YakmeshRegisterServer()
	var/list/data = list(
		"gameId" = YAKMESH_GAME_ID,
		"host" = world.internet_address || world.address,
		"port" = world.port,
		"name" = YAKMESH_SERVER_NAME,
		"maxPlayers" = YAKMESH_MAX_PLAYERS,
		"version" = DM_VERSION,
		"metadata" = list(
			"byond_version" = "[world.byond_version].[world.byond_build]"
		)
	)
	
	var/result = YakmeshRequest("/register", "POST", data)
	if(result && result["success"])
		yakmesh_server_id = result["serverId"]
		YakmeshLog("Server registered: [yakmesh_server_id]")
		return TRUE
	
	return FALSE

/**
 * Get list of other servers on the mesh
 * @param gameId Optional: filter by game ID
 */
/proc/YakmeshDiscoverServers(gameId = null)
	var/url = "/servers"
	if(gameId)
		url += "?gameId=[url_encode(gameId)]"
	
	var/result = YakmeshRequest(url, "GET")
	if(result && result["servers"])
		return result["servers"]
	
	return list()


// ═══════════════════════════════════════════════════════════════════════════════
// WORLD PERSISTENCE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Save the current world state to the Yakmesh mesh
 * @param metadata Optional metadata to attach to the save
 */
/proc/YakmeshSaveWorld(list/metadata = null)
	if(!yakmesh_server_id)
		YakmeshLog("ERROR: Cannot save - server not registered")
		return null
	
	// Collect world state (override YakmeshGetWorldState for custom logic)
	var/world_data = YakmeshGetWorldState()
	if(!world_data)
		YakmeshLog("ERROR: Failed to collect world state")
		return null
	
	var/list/data = list(
		"serverId" = yakmesh_server_id,
		"data" = world_data,
		"encoding" = "base64",
		"metadata" = metadata || list(
			"round_id" = "[world.realtime]",
			"players" = clients.len,
			"timestamp" = world.timeofday
		)
	)
	
	var/result = YakmeshRequest("/world/save", "POST", data)
	if(result && result["success"])
		yakmesh_last_save_cid = result["cid"]
		YakmeshLog("World saved: [yakmesh_last_save_cid]")
		return yakmesh_last_save_cid
	
	return null

/**
 * Load a world state from the Yakmesh mesh
 * @param cid Content ID of the save to load
 */
/proc/YakmeshLoadWorld(cid)
	var/result = YakmeshRequest("/world/load/[url_encode(cid)]", "GET")
	if(result && result["success"])
		var/world_data = result["data"]
		// Decode base64 if needed
		if(result["encoding"] == "base64")
			world_data = base64_decode(world_data)
		
		// Apply world state (override YakmeshApplyWorldState for custom logic)
		if(YakmeshApplyWorldState(world_data))
			YakmeshLog("World loaded: [cid]")
			return TRUE
	
	return FALSE

/**
 * Override this to customize how world state is collected
 * Default implementation uses savefile
 */
/proc/YakmeshGetWorldState()
	var/savefile/F = new()
	F["version"] = DM_VERSION
	F["round_id"] = world.realtime
	F["time"] = world.timeofday
	
	// Save turfs with important data
	var/list/turf_data = list()
	for(var/turf/T in world)
		if(T.yakmesh_persist)
			turf_data += list(list(
				"x" = T.x,
				"y" = T.y,
				"z" = T.z,
				"type" = "[T.type]",
				"data" = T.YakmeshSerialize()
			))
	F["turfs"] = turf_data
	
	// Save atoms with yakmesh_persist flag
	var/list/atom_data = list()
	for(var/atom/movable/A in world)
		if(A.yakmesh_persist)
			atom_data += list(list(
				"type" = "[A.type]",
				"x" = A.x,
				"y" = A.y,
				"z" = A.z,
				"data" = A.YakmeshSerialize()
			))
	F["atoms"] = atom_data
	
	return file2text(F.ExportText())

/**
 * Override this to customize how world state is applied
 */
/proc/YakmeshApplyWorldState(data)
	try
		var/savefile/F = new()
		F.ImportText("/", data)
		
		var/list/atom_data
		F["atoms"] >> atom_data
		
		for(var/list/entry in atom_data)
			var/atom/movable/A = locate(text2path(entry["type"]))
			if(A)
				A.Move(locate(entry["x"], entry["y"], entry["z"]))
				A.YakmeshDeserialize(entry["data"])
		
		return TRUE
	catch(var/exception/E)
		YakmeshLog("ERROR loading world: [E]")
		return FALSE

/// Auto-save loop
/proc/YakmeshAutoSaveLoop()
	while(yakmesh_initialized)
		sleep(YAKMESH_AUTO_SAVE_INTERVAL)
		YakmeshSaveWorld()


// ═══════════════════════════════════════════════════════════════════════════════
// PLAYER DOKO IDENTITIES
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check if a player has a DOKO identity
 * @param ckey Player's ckey
 */
/proc/YakmeshGetPlayerDoko(ckey)
	// Check cache first
	if(yakmesh_player_dokos[ckey])
		return yakmesh_player_dokos[ckey]
	
	var/result = YakmeshRequest("/doko/[url_encode(ckey)]", "GET")
	if(result && result["exists"])
		yakmesh_player_dokos[ckey] = result
		return result
	
	return null

/**
 * Create a DOKO identity for a player
 * @param ckey Player's ckey
 * @param claims Optional claims to attach
 */
/proc/YakmeshCreatePlayerDoko(ckey, list/claims = null)
	var/list/data = list(
		"ckey" = ckey,
		"claims" = claims
	)
	
	var/result = YakmeshRequest("/doko/create", "POST", data)
	if(result && result["success"])
		yakmesh_player_dokos[ckey] = result
		return result
	
	return null

/**
 * Verify a player's DOKO signature
 */
/proc/YakmeshVerifyPlayerDoko(ckey, challenge, signature)
	var/list/data = list(
		"ckey" = ckey,
		"challenge" = challenge,
		"signature" = signature
	)
	
	var/result = YakmeshRequest("/doko/verify", "POST", data)
	return result && result["valid"]


// ═══════════════════════════════════════════════════════════════════════════════
// TOPIC HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Handle incoming Yakmesh Topic requests
 * Add this to your world/Topic() proc
 */
/proc/YakmeshHandleTopic(T, Addr)
	// Check if this is a Yakmesh topic
	if(!findtext(T, "yakmesh"))
		return null
	
	var/list/params = params2list(T)
	var/action = params["yakmesh"]
	
	switch(action)
		if("status")
			return YakmeshTopicStatus()
		
		if("ping")
			return "pong"
		
		if("player_count")
			return "[clients.len]"
		
		if("save")
			var/cid = YakmeshSaveWorld()
			return cid ? "saved:[cid]" : "error:save_failed"
		
		if("challenge")
			// Sign a challenge for verification
			var/challenge = params["data"]
			return YakmeshSignChallenge(challenge)
	
	return "error:unknown_action"

/// Generate status response for Topic
/proc/YakmeshTopicStatus()
	var/list/status = list(
		"players" = clients.len,
		"maxplayers" = YAKMESH_MAX_PLAYERS,
		"gameId" = YAKMESH_GAME_ID,
		"version" = DM_VERSION,
		"yakmesh" = "1.0.0",
		"registered" = yakmesh_server_id ? "1" : "0"
	)
	
	var/result = ""
	for(var/key in status)
		if(result)
			result += "&"
		result += "[key]=[url_encode("[status[key]]")]"
	
	return result

/// Sign a challenge (for server verification)
/proc/YakmeshSignChallenge(challenge)
	// Simple HMAC-like signature using world params
	var/signature = md5("[challenge]-[world.port]-[YAKMESH_GAME_ID]")
	return signature


// ═══════════════════════════════════════════════════════════════════════════════
// HTTP REQUEST HELPER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Make an HTTP request to the Yakmesh bridge
 */
/proc/YakmeshRequest(path, method = "GET", list/data = null)
	var/url = "[YAKMESH_BRIDGE_URL][path]"
	
	try
		var/response
		if(method == "GET")
			response = world.Export(url)
		else
			// POST with JSON body
			var/json_body = json_encode(data)
			response = world.Export(url, json_body)
		
		if(response)
			var/text = file2text(response)
			if(text)
				return json_decode(text)
		
		return null
	catch(var/exception/E)
		YakmeshLog("ERROR: Request failed - [E]")
		return null


// ═══════════════════════════════════════════════════════════════════════════════
// SERIALIZATION HOOKS
// ═══════════════════════════════════════════════════════════════════════════════

/// Flag atoms for persistence (set to TRUE on atoms you want saved)
/atom/var/yakmesh_persist = FALSE

/// Override to customize serialization
/atom/proc/YakmeshSerialize()
	return list()

/// Override to customize deserialization
/atom/proc/YakmeshDeserialize(list/data)
	return


// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ═══════════════════════════════════════════════════════════════════════════════

/// Debug logging
/proc/YakmeshLog(message)
	#if YAKMESH_DEBUG
	world.log << "\[YAKMESH] [message]"
	#endif
	// Always log errors
	if(findtext(message, "ERROR"))
		world.log << "\[YAKMESH] [message]"
