<#
.SYNOPSIS
    Start YAKMESH Minimal Node

.DESCRIPTION
    Starts the Yakmesh mesh node, content API, and Caddy web server.
    Downloads Caddy on first run if not present.
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host ""
Write-Host "  =====================================" -ForegroundColor Cyan
Write-Host "      YAKMESH MINIMAL NODE" -ForegroundColor Cyan
Write-Host "      Mesh Network + Web Server" -ForegroundColor Cyan
Write-Host "  =====================================" -ForegroundColor Cyan
Write-Host ""

# Check Node.js
$nodeVersion = & node --version 2>$null
if (-not $nodeVersion) {
    Write-Host "[ERROR] Node.js not found. Please install Node.js 18+ and add to PATH." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Node.js $nodeVersion" -ForegroundColor Green

# Check/Install dependencies
if (-not (Test-Path "node_modules")) {
    Write-Host "[INFO] Installing dependencies..." -ForegroundColor Yellow
    & npm install
}

# Check Caddy
$caddyPath = Join-Path $ScriptDir "bin\caddy.exe"
if (-not (Test-Path $caddyPath)) {
    Write-Host "[INFO] Downloading Caddy web server..." -ForegroundColor Yellow
    
    # Create bin directory
    New-Item -ItemType Directory -Path (Join-Path $ScriptDir "bin") -Force | Out-Null
    
    # Download Caddy
    $caddyUrl = "https://github.com/caddyserver/caddy/releases/download/v2.8.4/caddy_2.8.4_windows_amd64.zip"
    $zipPath = Join-Path $ScriptDir "bin\caddy.zip"
    
    Invoke-WebRequest -Uri $caddyUrl -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath (Join-Path $ScriptDir "bin") -Force
    Remove-Item $zipPath
    
    Write-Host "[OK] Caddy installed" -ForegroundColor Green
}

# Create directories
@("htdocs", "data", "data\content", "logs") | ForEach-Object {
    $dir = Join-Path $ScriptDir $_
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Create default index.html if not exists
$indexPath = Join-Path $ScriptDir "htdocs\index.html"
if (-not (Test-Path $indexPath)) {
    @"
<!DOCTYPE html>
<html>
<head>
    <title>YAKMESH Node</title>
    <style>
        body { font-family: system-ui; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #2d5016; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>🦬 YAKMESH Node Running</h1>
    <p>Your Yakmesh node is operational.</p>
    <h2>Endpoints</h2>
    <ul>
        <li><strong>Web Server:</strong> <a href="http://localhost:8080">http://localhost:8080</a></li>
        <li><strong>Content API:</strong> <a href="http://localhost:3000/content">http://localhost:3000/content</a></li>
        <li><strong>Mesh P2P:</strong> <code>ws://localhost:9001</code></li>
    </ul>
    <h2>Content API</h2>
    <ul>
        <li><code>GET /content</code> - List all content</li>
        <li><code>GET /content/:hash</code> - Get content by hash</li>
        <li><code>POST /content</code> - Store new content</li>
    </ul>
    <p><a href="https://yakmesh.dev">yakmesh.dev</a> | <a href="https://github.com/yakmesh/yakmesh">GitHub</a></p>
</body>
</html>
"@ | Out-File -FilePath $indexPath -Encoding utf8
}

Write-Host ""
Write-Host "[INFO] Starting services..." -ForegroundColor Yellow
Write-Host ""

# Start Yakmesh node in background
$env:YAKMESH_CONFIG = Join-Path $ScriptDir "config\yakmesh.config.js"
$meshJob = Start-Job -ScriptBlock {
    param($dir)
    Set-Location $dir
    & node server/index.js 2>&1
} -ArgumentList $ScriptDir

# Give mesh node time to start
Start-Sleep -Seconds 2

# Start Caddy
$caddyfile = Join-Path $ScriptDir "config\Caddyfile"
$caddyJob = Start-Job -ScriptBlock {
    param($caddy, $config, $dir)
    Set-Location $dir
    & $caddy run --config $config 2>&1
} -ArgumentList $caddyPath, $caddyfile, $ScriptDir

Write-Host ""
Write-Host "  ✓ Mesh Node:     ws://localhost:9001" -ForegroundColor Green
Write-Host "  ✓ Content API:   http://localhost:3000" -ForegroundColor Green
Write-Host "  ✓ Web Server:    http://localhost:8080" -ForegroundColor Green
Write-Host ""
Write-Host "  Press Ctrl+C to stop all services" -ForegroundColor Yellow
Write-Host ""

# Save PIDs for stop script
@{
    meshJobId = $meshJob.Id
    caddyJobId = $caddyJob.Id
    startTime = Get-Date -Format "o"
} | ConvertTo-Json | Out-File (Join-Path $ScriptDir "data\.pids.json")

# Wait and handle Ctrl+C
try {
    while ($true) {
        Start-Sleep -Seconds 1
        
        # Check if jobs are still running
        $meshState = Get-Job -Id $meshJob.Id -ErrorAction SilentlyContinue
        $caddyState = Get-Job -Id $caddyJob.Id -ErrorAction SilentlyContinue
        
        if ($meshState.State -eq "Failed" -or $caddyState.State -eq "Failed") {
            Write-Host "[ERROR] A service has stopped unexpectedly" -ForegroundColor Red
            break
        }
    }
}
finally {
    Write-Host ""
    Write-Host "[INFO] Shutting down..." -ForegroundColor Yellow
    
    Stop-Job -Id $meshJob.Id -ErrorAction SilentlyContinue
    Stop-Job -Id $caddyJob.Id -ErrorAction SilentlyContinue
    Remove-Job -Id $meshJob.Id -Force -ErrorAction SilentlyContinue
    Remove-Job -Id $caddyJob.Id -Force -ErrorAction SilentlyContinue
    
    # Also kill any orphan processes
    Get-Process -Name "caddy" -ErrorAction SilentlyContinue | Stop-Process -Force
    
    Remove-Item (Join-Path $ScriptDir "data\.pids.json") -ErrorAction SilentlyContinue
    
    Write-Host "[OK] All services stopped" -ForegroundColor Green
}
