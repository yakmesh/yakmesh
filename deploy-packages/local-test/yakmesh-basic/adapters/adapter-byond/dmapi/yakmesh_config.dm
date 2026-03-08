// ═══════════════════════════════════════════════════════════════════════════════
// YAKMESH DMAPI - Minimal Configuration
// ═══════════════════════════════════════════════════════════════════════════════
// 
// Copy this file to your project and modify the settings below.
// Then #include this BEFORE yakmesh.dm
// 
// @version 1.0.0
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// REQUIRED: Configure these for your game
// ═══════════════════════════════════════════════════════════════════════════════

/// URL of the Yakmesh HTTP bridge
#define YAKMESH_BRIDGE_URL "http://127.0.0.1:8080"

/// Your game's unique identifier
#define YAKMESH_GAME_ID "pondera"

/// Your server's display name  
#define YAKMESH_SERVER_NAME "Pondera Server"

/// Maximum players
#define YAKMESH_MAX_PLAYERS 50


// ═══════════════════════════════════════════════════════════════════════════════
// OPTIONAL: Feature toggles
// ═══════════════════════════════════════════════════════════════════════════════

/// Enable debug logging (0 = off, 1 = on)
#define YAKMESH_DEBUG 1

/// Auto-register server on startup
#define YAKMESH_AUTO_REGISTER 1

/// Auto-save interval in deciseconds (0 = disabled, 6000 = 10 minutes)
#define YAKMESH_AUTO_SAVE_INTERVAL 0

/// API key for secured bridges (null = no auth)
#define YAKMESH_API_KEY null
