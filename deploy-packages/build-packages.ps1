<#
.SYNOPSIS
    Build YAKMESH deployment packages

.DESCRIPTION
    Builds deployment variants:
    - yakmesh-minimal: Barebones Node.js mesh node (core only)
    - yakmesh-basic: Standard deployment with extras
    - yakmesh-full: Self-contained with all binaries (Caddy, PHP, Node.js)
    - yakbot: Discord community bot (standalone)

.PARAMETER Target
    Which package to build: 'minimal', 'basic', 'full', 'yakbot', or 'all' (default)

.EXAMPLE
    .\build-packages.ps1 -Target minimal
    .\build-packages.ps1 -Target yakbot
    .\build-packages.ps1 -Target all

.NOTES
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║  DEPLOYMENT RULE — READ THIS BEFORE TOUCHING THIS FILE                  ║
    ║                                                                         ║
    ║  The build/ directory is for BUILD OUTPUT ONLY.                          ║
    ║                                                                         ║
    ║  NEVER run 'npm install', 'node server/index.js', or launch any         ║
    ║  process from inside build/. Doing so creates runtime files             ║
    ║  (machine-seed.json, node-key.json, yakmesh.db, sponge state)           ║
    ║  that contaminate the build and will BREAK other machines when           ║
    ║  the package is deployed — especially machine-seed.json which           ║
    ║  is hardware-encrypted and cannot be decrypted on any other machine.    ║
    ║                                                                         ║
    ║  CORRECT workflow:                                                      ║
    ║    1. Run this script to build the package                              ║
    ║    2. Copy build/yakmesh-basic/ (or .zip) to the deployment target      ║
    ║    3. Run 'npm install' and 'node server/index.js' THERE                ║
    ║                                                                         ║
    ║  UPGRADE workflow (existing deployment):                                ║
    ║    1. Build the package (this script)                                   ║
    ║    2. Copy source dirs (server/, mesh/, oracle/, etc.) over the         ║
    ║       existing deployment — but DO NOT overwrite data/                  ║
    ║    3. ALSO copy data/manifest.json from the build output.               ║
    ║       This is the ONE file in data/ that MUST be updated on upgrades.   ║
    ║       Without it the oracle sees stale files → renames them →           ║
    ║       oracle hash changes → JHILKE bootstrap key differs →             ║
    ║       ANNEX "unable to authenticate" errors between nodes.             ║
    ║    4. The existing machine-seed.json, node-key.json, and database       ║
    ║       stay intact. The node keeps its identity. nodeId will change      ║
    ║       (new oracle hash = new code proven) but persistentId is stable.   ║
    ║                                                                         ║
    ║  These are DEPLOYMENT packages. Build them, then deploy them elsewhere. ║
    ╚═══════════════════════════════════════════════════════════════════════════╝

    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║  AGENT INSTRUCTIONS — MANDATORY FOR ALL AI CODING AGENTS                ║
    ║                                                                         ║
    ║  If you are an AI agent (Copilot, Cursor, Cline, Windsurf, etc.)        ║
    ║  READ AND FOLLOW these rules. Violations cause production failures.     ║
    ║                                                                         ║
    ║  ┌─────────────────────────────────────────────────────────────────────┐ ║
    ║  │  RULE 1: MANIFEST MUST BE REGENERATED AFTER ANY FILE CHANGES       │ ║
    ║  │                                                                     │ ║
    ║  │  The iO manifest (data/manifest.json) is the oracle's file list.   │ ║
    ║  │  It contains a buildNonce that feeds into the JHILKE bootstrap      │ ║
    ║  │  key derivation. If the manifest does not match the actual files:   │ ║
    ║  │                                                                     │ ║
    ║  │    → Oracle detects "files not in manifest"                        │ ║
    ║  │    → Stale files get renamed to .pruned                            │ ║
    ║  │    → Oracle hash changes (different files hashed)                  │ ║
    ║  │    → JHILKE derives a different bootstrap key                      │ ║
    ║  │    → ANNEX AES-GCM decryption fails between nodes                 │ ║
    ║  │    → "Unsupported state or unable to authenticate data"            │ ║
    ║  │                                                                     │ ║
    ║  │  AFTER modifying, adding, or removing ANY .js file:                │ ║
    ║  │    1. Run this build script (it regenerates the manifest)           │ ║
    ║  │    2. Deploy the new manifest WITH the new source files             │ ║
    ║  │                                                                     │ ║
    ║  │  The build script calls generate-manifest.js automatically.         │ ║
    ║  │  You do NOT need to run it manually — just run build-packages.ps1. │ ║
    ║  └─────────────────────────────────────────────────────────────────────┘ ║
    ║                                                                         ║
    ║  ┌─────────────────────────────────────────────────────────────────────┐ ║
    ║  │  RULE 2: UPGRADE DEPLOYMENTS MUST INCLUDE data/manifest.json       │ ║
    ║  │                                                                     │ ║
    ║  │  When upgrading an existing node (copying source dirs over):        │ ║
    ║  │    - Copy all source directories (server/, mesh/, oracle/, etc.)    │ ║
    ║  │    - ALSO copy data/manifest.json from the build output             │ ║
    ║  │    - Do NOT copy data/machine-seed.json (hardware-encrypted)        │ ║
    ║  │    - Do NOT copy data/node-key.json (derived from seed)             │ ║
    ║  │    - Do NOT copy data/yakmesh.db (runtime database)                │ ║
    ║  │    - Do NOT copy data/prahari-sponge-v3.json (entropy state)        │ ║
    ║  │                                                                     │ ║
    ║  │  Files to copy on upgrade:                                          │ ║
    ║  │    source dirs + core files + data/manifest.json                    │ ║
    ║  │                                                                     │ ║
    ║  │  Files to NEVER copy on upgrade:                                    │ ║
    ║  │    data/machine-seed.json, data/node-key.json, data/yakmesh.db,    │ ║
    ║  │    data/prahari-sponge-v3.json, data/yakmesh.db-wal, logs/         │ ║
    ║  └─────────────────────────────────────────────────────────────────────┘ ║
    ║                                                                         ║
    ║  ┌─────────────────────────────────────────────────────────────────────┐ ║
    ║  │  RULE 3: PORT DIFFERENTIATION VIA ENV VARS ONLY                    │ ║
    ║  │                                                                     │ ║
    ║  │  yakmesh.config.js MUST stay byte-identical across ALL nodes.       │ ║
    ║  │  The Validation Oracle hashes ALL .js files — changing config       │ ║
    ║  │  creates a different network, cryptographically isolating nodes.    │ ║
    ║  │                                                                     │ ║
    ║  │  Use environment variables for per-node settings:                   │ ║
    ║  │    YAKMESH_HTTP_PORT  (default 3080)                               │ ║
    ║  │    YAKMESH_WS_PORT    (default 9080)                               │ ║
    ║  │    YAKMESH_DATA_DIR   (default ./data)                             │ ║
    ║  │    YAKMESH_BOOTSTRAP  (comma-separated ws:// URLs)                 │ ║
    ║  │    YAKMESH_DOMAIN     (for ACME/TLS)                               │ ║
    ║  │    YAKMESH_ACME_EMAIL (for Let's Encrypt)                          │ ║
    ║  │    YAKMESH_SELF_ENDPOINT (public-facing URL)                       │ ║
    ║  │                                                                     │ ║
    ║  │  NEVER modify yakmesh.config.js per-node. EVER.                    │ ║
    ║  └─────────────────────────────────────────────────────────────────────┘ ║
    ║                                                                         ║
    ║  ┌─────────────────────────────────────────────────────────────────────┐ ║
    ║  │  RULE 4: NEVER WRITE .js FILES AT RUNTIME                          │ ║
    ║  │                                                                     │ ║
    ║  │  Test scripts, config generators, or any code that creates or       │ ║
    ║  │  modifies .js files at runtime will change the oracle hash and      │ ║
    ║  │  cryptographically isolate the node from the network.              │ ║
    ║  └─────────────────────────────────────────────────────────────────────┘ ║
    ║                                                                         ║
    ║  ┌─────────────────────────────────────────────────────────────────────┐ ║
    ║  │  RULE 5: build/ IS OUTPUT ONLY                                     │ ║
    ║  │                                                                     │ ║
    ║  │  NEVER run npm install, node server/index.js, or any process       │ ║
    ║  │  from inside build/. This creates machine-specific runtime files    │ ║
    ║  │  (machine-seed.json is hardware-encrypted) that contaminate the    │ ║
    ║  │  build and BREAK deployments to other machines.                     │ ║
    ║  │                                                                     │ ║
    ║  │  Build → Copy to target → Run at target. Always.                   │ ║
    ║  └─────────────────────────────────────────────────────────────────────┘ ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
#>

param(
    [ValidateSet('minimal', 'basic', 'full', 'yakbot', 'all')]
    [string]$Target = 'all'
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceDir = Split-Path -Parent $ScriptDir  # yakmesh-node directory
$BuildDir = Join-Path $ScriptDir "build"
$DownloadDir = Join-Path $ScriptDir "downloads"

# Version configuration for full package binaries
$Versions = @{
    Caddy = "2.8.4"
    PHP = "8.3.29"
    Node = "20.18.0"
}

$Downloads = @{
    Caddy = "https://github.com/caddyserver/caddy/releases/download/v$($Versions.Caddy)/caddy_$($Versions.Caddy)_windows_amd64.zip"
    PHP = "https://windows.php.net/downloads/releases/php-$($Versions.PHP)-nts-Win32-vs16-x64.zip"
    Node = "https://nodejs.org/dist/v$($Versions.Node)/node-v$($Versions.Node)-win-x64.zip"
}

# =============================================================================
# PACKAGE DEFINITIONS
# =============================================================================

# MINIMAL: Absolute barebones - just what's needed to run a mesh node
$MinimalDirs = @(
    'server',        # Express server entry point
    'mesh',          # P2P networking, WebSocket, SHERPA, Annex
    'gossip',        # Gossip protocol
    'oracle',        # Distributed oracle, consensus, code proof
    'identity',      # Node identity (ML-DSA-65)
    'content',       # Content store and API
    'database',      # SQLite/replication
    'protocol',      # Protocol definitions
    'security',      # Rate limiting, validation
    'utils',         # Logger, helpers
    'embedded-docs'  # Inline documentation server
)

# BASIC: Minimal + useful extras for standard deployments
$BasicDirs = $MinimalDirs + @(
    'adapters',      # PeerQuanta adapters (listings, chat, forum)
    'dashboard',     # Web dashboard UI (legacy, also in public/)
    'public',        # Unified web root (dashboard, assets, C2C art, YakAI)
    'webserver',     # Static file serving
    'templates'      # Template files
    # NOTE: 'announcements' excluded — Discord/Telegram/X marketing, not needed at runtime
)

# FULL: Basic + CLI, yakbot, and bundled binaries
$FullDirs = $BasicDirs + @(
    'cli'            # Command line interface
    # Note: yakbot excluded - has its own node_modules (26MB)
)

# Core files to include in all packages
$CoreFiles = @(
    'package.json',
    'package-lock.json',
    'ecosystem.config.json',
    'yakmesh.config.js',
    'yakmesh.config.example.js',
    'yakmesh.config.production.js',
    'LICENSE',
    'README.md',
    'CHANGELOG.md',
    'start-yakmesh.bat'
)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

function Download-File {
    param([string]$Url, [string]$OutFile)
    
    if (Test-Path $OutFile) {
        Write-Host "    [CACHED] $(Split-Path $OutFile -Leaf)" -ForegroundColor Gray
        return
    }
    
    Write-Host "    [DOWNLOAD] $(Split-Path $OutFile -Leaf)" -ForegroundColor Cyan
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
}

function Copy-PackageSource {
    param(
        [string]$DestDir,
        [string[]]$Directories,
        [switch]$IncludeNodeModules
    )
    
    # Copy specified directories
    foreach ($dir in $Directories) {
        $srcPath = Join-Path $SourceDir $dir
        if (Test-Path $srcPath) {
            Copy-Item $srcPath -Destination $DestDir -Recurse -Force
            Write-Host "    [COPY] $dir" -ForegroundColor Gray
        } else {
            Write-Host "    [SKIP] $dir (not found)" -ForegroundColor Yellow
        }
    }
    
    # Copy core files
    foreach ($file in $CoreFiles) {
        $srcPath = Join-Path $SourceDir $file
        if (Test-Path $srcPath) {
            Copy-Item $srcPath -Destination $DestDir -Force
        }
    }
    
    # Copy node_modules if requested (ensures identical codebase hash across deployments)
    if ($IncludeNodeModules) {
        $nodeModulesPath = Join-Path $SourceDir "node_modules"
        if (Test-Path $nodeModulesPath) {
            Write-Host "    [COPY] node_modules (this ensures identical codebase hash)" -ForegroundColor Cyan
            Copy-Item $nodeModulesPath -Destination $DestDir -Recurse -Force
        }
    }
    
    # Strip test files and directories — not needed in production deploys
    $testDirs = Get-ChildItem $DestDir -Recurse -Directory -Filter "tests" -ErrorAction SilentlyContinue
    foreach ($td in $testDirs) {
        Remove-Item $td.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    $testFiles = Get-ChildItem $DestDir -Recurse -File -Include "*.test.js","*.spec.js","*.test.mjs","*.spec.mjs" -ErrorAction SilentlyContinue
    $stripped = ($testDirs.Count + ($testFiles | Measure-Object).Count)
    foreach ($tf in $testFiles) {
        Remove-Item $tf.FullName -Force -ErrorAction SilentlyContinue
    }
    if ($stripped -gt 0) {
        Write-Host "    [STRIP] Removed $stripped test files/dirs" -ForegroundColor DarkGray
    }

    # Create empty runtime directories
    @("data", "data/content", "logs") | ForEach-Object {
        New-Item -ItemType Directory -Path (Join-Path $DestDir $_) -Force | Out-Null
    }

    # Clean runtime-generated files that must NOT ship in packages
    # These are machine-specific (encrypted to hardware) or ephemeral
    $runtimeFiles = @(
        "data/machine-seed.json",    # Hardware-encrypted identity — cannot transfer between machines
        "data/node-key.json",        # ML-DSA-65 keypair derived from seed
        "data/prahari-sponge-v3.json", # Entropy state — machine-specific
        "data/yakmesh.db",           # Runtime database
        "data/yakmesh.db-wal",
        "data/yakmesh.db-shm"
    )
    $cleaned = 0
    foreach ($rf in $runtimeFiles) {
        $rfPath = Join-Path $DestDir $rf
        if (Test-Path $rfPath) {
            Remove-Item $rfPath -Force -ErrorAction SilentlyContinue
            $cleaned++
        }
    }
    # Also clean any website cache dirs that might appear
    $dataDirClean = Join-Path (Join-Path $DestDir "data") "websites"
    if (Test-Path $dataDirClean) {
        Remove-Item $dataDirClean -Recurse -Force -ErrorAction SilentlyContinue
        $cleaned++
    }
    if ($cleaned -gt 0) {
        Write-Host "    [CLEAN] Removed $cleaned runtime-generated files from data/" -ForegroundColor DarkGray
    }
}

function Get-PackageStats {
    param([string]$Dir)
    
    $files = Get-ChildItem $Dir -Recurse -File -ErrorAction SilentlyContinue
    $count = $files.Count
    $size = ($files | Measure-Object Length -Sum).Sum
    
    return @{
        Files = $count
        SizeKB = [math]::Round($size / 1KB, 1)
        SizeMB = [math]::Round($size / 1MB, 2)
    }
}

# =============================================================================
# BUILD FUNCTIONS
# =============================================================================

function Generate-Manifest {
    param([string]$PackageDir)

    $manifestScript = Join-Path $ScriptDir "generate-manifest.js"
    if (Test-Path $manifestScript) {
        Write-Host "  Generating iO manifest..." -ForegroundColor Yellow
        & node $manifestScript --root $PackageDir 2>&1 | ForEach-Object {
            Write-Host "    $_" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [SKIP] generate-manifest.js not found" -ForegroundColor Yellow
    }
}

function Build-Minimal {
    Write-Host ""
    Write-Host "Building MINIMAL package (barebones mesh node)..." -ForegroundColor Green
    Write-Host "  Includes: server, mesh, gossip, oracle, identity, content, database, protocol, security, utils" -ForegroundColor Gray
    
    $minimalDir = Join-Path $BuildDir "yakmesh-minimal"
    
    # Clean and create
    if (Test-Path $minimalDir) { Remove-Item $minimalDir -Recurse -Force }
    New-Item -ItemType Directory -Path $minimalDir -Force | Out-Null
    
    # Copy source
    Write-Host "  Copying source files..." -ForegroundColor Yellow
    Copy-PackageSource -DestDir $minimalDir -Directories $MinimalDirs
    
    # Generate iO file manifest
    Generate-Manifest -PackageDir $minimalDir
    
    # Get stats
    $stats = Get-PackageStats -Dir $minimalDir
    
    # Create zip
    $zipPath = Join-Path $BuildDir "yakmesh-minimal.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath }
    
    Write-Host "  Creating archive..." -ForegroundColor Yellow
    Compress-Archive -Path "$minimalDir\*" -DestinationPath $zipPath -CompressionLevel Optimal
    
    $zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    Write-Host "  [OK] yakmesh-minimal.zip ($zipSize MB, $($stats.Files) files)" -ForegroundColor Green
    
    return $minimalDir
}

function Build-Basic {
    Write-Host ""
    Write-Host "Building BASIC package (standard deployment)..." -ForegroundColor Green
    Write-Host "  Includes: minimal + adapters, dashboard, webserver, templates" -ForegroundColor Gray
    
    $basicDir = Join-Path $BuildDir "yakmesh-basic"
    
    # Clean and create
    if (Test-Path $basicDir) { Remove-Item $basicDir -Recurse -Force }
    New-Item -ItemType Directory -Path $basicDir -Force | Out-Null
    
    # Copy source
    Write-Host "  Copying source files..." -ForegroundColor Yellow
    Copy-PackageSource -DestDir $basicDir -Directories $BasicDirs
    
    # Generate iO file manifest
    Generate-Manifest -PackageDir $basicDir
    
    # Get stats
    $stats = Get-PackageStats -Dir $basicDir
    
    # Create zip
    $zipPath = Join-Path $BuildDir "yakmesh-basic.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath }
    
    Write-Host "  Creating archive..." -ForegroundColor Yellow
    Compress-Archive -Path "$basicDir\*" -DestinationPath $zipPath -CompressionLevel Optimal
    
    $zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    Write-Host "  [OK] yakmesh-basic.zip ($zipSize MB, $($stats.Files) files)" -ForegroundColor Green
    
    return $basicDir
}

function Build-Full {
    Write-Host ""
    Write-Host "Building FULL package (self-contained with binaries)..." -ForegroundColor Green
    Write-Host "  Includes: basic + CLI + Caddy $($Versions.Caddy) + PHP $($Versions.PHP) + Node $($Versions.Node)" -ForegroundColor Gray
    
    $fullDir = Join-Path $BuildDir "yakmesh-full"
    
    # Clean and create
    if (Test-Path $fullDir) { Remove-Item $fullDir -Recurse -Force }
    New-Item -ItemType Directory -Path $fullDir -Force | Out-Null
    
    # Create download directory
    New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
    
    # Download binaries
    Write-Host "  Downloading binaries..." -ForegroundColor Yellow
    
    $caddyZip = Join-Path $DownloadDir "caddy.zip"
    Download-File -Url $Downloads.Caddy -OutFile $caddyZip
    
    $phpZip = Join-Path $DownloadDir "php.zip"
    Download-File -Url $Downloads.PHP -OutFile $phpZip
    
    $nodeZip = Join-Path $DownloadDir "node.zip"
    Download-File -Url $Downloads.Node -OutFile $nodeZip
    
    # Copy yakmesh source
    Write-Host "  Copying source files..." -ForegroundColor Yellow
    Copy-PackageSource -DestDir $fullDir -Directories $FullDirs
    
    # Create bin directory
    $binDir = Join-Path $fullDir "bin"
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    
    # Extract Caddy
    Write-Host "  Extracting Caddy..." -ForegroundColor Yellow
    Expand-Archive -Path $caddyZip -DestinationPath $binDir -Force
    
    # Extract PHP
    Write-Host "  Extracting PHP..." -ForegroundColor Yellow
    $phpDir = Join-Path $binDir "php"
    New-Item -ItemType Directory -Path $phpDir -Force | Out-Null
    Expand-Archive -Path $phpZip -DestinationPath $phpDir -Force
    
    # Extract Node
    Write-Host "  Extracting Node.js..." -ForegroundColor Yellow
    $nodeTmpDir = Join-Path $DownloadDir "node-tmp"
    if (Test-Path $nodeTmpDir) { Remove-Item $nodeTmpDir -Recurse -Force }
    Expand-Archive -Path $nodeZip -DestinationPath $nodeTmpDir -Force
    $nodeExtracted = Get-ChildItem $nodeTmpDir | Select-Object -First 1
    $nodeDir = Join-Path $binDir "node"
    Move-Item $nodeExtracted.FullName $nodeDir -Force
    Remove-Item $nodeTmpDir -Recurse -Force
    
    # Copy full package configs if they exist
    $fullCfg = Join-Path $ScriptDir "yakmesh-full"
    if (Test-Path $fullCfg) {
        if (Test-Path (Join-Path $fullCfg "config")) {
            Copy-Item (Join-Path $fullCfg "config") -Destination $fullDir -Recurse -Force
        }
        Get-ChildItem $fullCfg -Filter "*.ps1" -ErrorAction SilentlyContinue | Copy-Item -Destination $fullDir -Force
        Get-ChildItem $fullCfg -Filter "*.sh" -ErrorAction SilentlyContinue | Copy-Item -Destination $fullDir -Force
    }
    
    # Ensure public/ web root exists (Caddy serves from here)
    $publicDir = Join-Path $fullDir "public"
    if (-not (Test-Path $publicDir)) {
        New-Item -ItemType Directory -Path $publicDir -Force | Out-Null
    }
    # Add PHP info page for testing
    "<?php phpinfo();" | Out-File -FilePath (Join-Path $publicDir "info.php") -Encoding utf8
    
    # Generate iO manifest
    Generate-Manifest -PackageDir $fullDir

    # Get stats
    $stats = Get-PackageStats -Dir $fullDir
    
    # Create zip
    $zipPath = Join-Path $BuildDir "yakmesh-full-win-x64.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath }
    
    Write-Host "  Creating archive..." -ForegroundColor Yellow
    Compress-Archive -Path "$fullDir\*" -DestinationPath $zipPath -CompressionLevel Optimal
    
    $zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    Write-Host "  [OK] yakmesh-full-win-x64.zip ($zipSize MB, $($stats.Files) files)" -ForegroundColor Green
    
    return $fullDir
}

function Build-Yakbot {
    Write-Host ""
    Write-Host "Building YAKBOT package (Discord bot)..." -ForegroundColor Green
    Write-Host "  Standalone Discord community bot for YAKMESH" -ForegroundColor Gray
    
    $yakbotSource = Join-Path $SourceDir "yakbot"
    $yakbotDir = Join-Path $BuildDir "yakbot"
    
    # Check source exists
    if (-not (Test-Path $yakbotSource)) {
        Write-Host "  [ERROR] YakBot source not found at: $yakbotSource" -ForegroundColor Red
        return $null
    }
    
    # Clean and create
    if (Test-Path $yakbotDir) { Remove-Item $yakbotDir -Recurse -Force }
    New-Item -ItemType Directory -Path $yakbotDir -Force | Out-Null
    
    # Files to copy
    $YakbotFiles = @(
        'index.js',
        'register-commands.js',
        'package.json',
        'package-lock.json',
        '.env.example',
        '.gitignore'
    )
    
    foreach ($file in $YakbotFiles) {
        $srcPath = Join-Path $yakbotSource $file
        if (Test-Path $srcPath) {
            Copy-Item $srcPath -Destination $yakbotDir -Force
            Write-Host "    [COPY] $file" -ForegroundColor Gray
        }
    }
    
    # Copy utils directory (needed for logger)
    $utilsSource = Join-Path $SourceDir "utils"
    $utilsDest = Join-Path $yakbotDir "utils"
    if (Test-Path $utilsSource) {
        New-Item -ItemType Directory -Path $utilsDest -Force | Out-Null
        Copy-Item "$utilsSource\*" -Destination $utilsDest -Recurse -Force
        Write-Host "    [COPY] utils/" -ForegroundColor Gray
    }
    
    # Copy deployment README
    $deployReadme = Join-Path $ScriptDir "yakbot\README.md"
    if (Test-Path $deployReadme) {
        Copy-Item $deployReadme -Destination $yakbotDir -Force
        Write-Host "    [COPY] README.md (deployment)" -ForegroundColor Gray
    }
    
    # Get stats
    $stats = Get-PackageStats -Dir $yakbotDir
    
    # Create zip
    $zipPath = Join-Path $BuildDir "yakbot.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath }
    
    Write-Host "  Creating archive..." -ForegroundColor Yellow
    Compress-Archive -Path "$yakbotDir\*" -DestinationPath $zipPath -CompressionLevel Optimal
    
    $zipSize = [math]::Round((Get-Item $zipPath).Length / 1KB, 1)
    Write-Host "  [OK] yakbot.zip ($zipSize KB, $($stats.Files) files)" -ForegroundColor Green
    
    return $yakbotDir
}

# =============================================================================
# MAIN
# =============================================================================

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  YAKMESH Package Builder v3.1" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Source: $SourceDir" -ForegroundColor Gray
Write-Host "Output: $BuildDir" -ForegroundColor Gray
Write-Host ""
Write-Host "Package Tiers:" -ForegroundColor Yellow
Write-Host "  minimal - Barebones mesh node (smallest)" -ForegroundColor White
Write-Host "  basic   - Standard deployment with extras" -ForegroundColor White
Write-Host "  full    - Self-contained (Caddy + PHP + Node)" -ForegroundColor White
Write-Host "  yakbot  - Discord community bot (standalone)" -ForegroundColor White
Write-Host ""

# Create build directory
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null

switch ($Target) {
    'minimal' { Build-Minimal }
    'basic' { Build-Basic }
    'full' { Build-Full }
    'yakbot' { Build-Yakbot }
    'all' {
        Build-Minimal
        Build-Basic
        Build-Full
        Build-Yakbot
    }
}

Write-Host ""
Write-Host "=====================================" -ForegroundColor Green
Write-Host "  Build Complete!" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green
Write-Host ""
Write-Host "Packages created:" -ForegroundColor Cyan
Get-ChildItem $BuildDir -Filter "*.zip" | Sort-Object Name | ForEach-Object {
    $size = [math]::Round($_.Length / 1MB, 2)
    Write-Host "  - $($_.Name) ($size MB)"
}
Write-Host ""
Write-Host "Unzipped directories available in: $BuildDir" -ForegroundColor Gray
Write-Host ""
