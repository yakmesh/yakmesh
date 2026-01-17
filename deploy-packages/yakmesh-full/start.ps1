<#
.SYNOPSIS
    Start YAKMESH Self-Contained Node

.DESCRIPTION
    Starts the complete Yakmesh stack using bundled binaries:
    - Node.js (bundled)
    - Caddy web server (bundled)
    - PHP FastCGI (bundled)
    
    No external dependencies required.
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host ""
Write-Host "  =====================================" -ForegroundColor Cyan
Write-Host "      YAKMESH SELF-CONTAINED" -ForegroundColor Cyan
Write-Host "      Complete Stack - All Bundled" -ForegroundColor Cyan
Write-Host "  =====================================" -ForegroundColor Cyan
Write-Host ""

# Paths to bundled binaries
$nodeBin = Join-Path $ScriptDir "bin\node\node.exe"
$caddyBin = Join-Path $ScriptDir "bin\caddy.exe"
$phpBin = Join-Path $ScriptDir "bin\php\php-cgi.exe"
$phpIni = Join-Path $ScriptDir "bin\php\php.ini"

# Verify bundled binaries exist
$missing = @()
if (-not (Test-Path $nodeBin)) { $missing += "Node.js (bin/node/node.exe)" }
if (-not (Test-Path $caddyBin)) { $missing += "Caddy (bin/caddy.exe)" }
if (-not (Test-Path $phpBin)) { $missing += "PHP (bin/php/php-cgi.exe)" }

if ($missing.Count -gt 0) {
    Write-Host "[ERROR] Missing bundled binaries:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Host ""
    Write-Host "This is a self-contained package. Binaries should be included." -ForegroundColor Yellow
    Write-Host "Please re-download the full package from yakmesh.dev" -ForegroundColor Yellow
    exit 1
}

# Show versions
$nodeVersion = & $nodeBin --version
Write-Host "[OK] Node.js $nodeVersion (bundled)" -ForegroundColor Green

$phpVersion = & $phpBin -v 2>$null | Select-Object -First 1
Write-Host "[OK] PHP $($phpVersion -replace 'PHP (\d+\.\d+\.\d+).*','$1') (bundled)" -ForegroundColor Green

$caddyVersion = & $caddyBin version 2>$null
Write-Host "[OK] Caddy $caddyVersion (bundled)" -ForegroundColor Green

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
        body { font-family: system-ui; max-width: 800px; margin: 50px auto; padding: 20px; background: #f8f9fa; }
        h1 { color: #2d5016; }
        code { background: #e9ecef; padding: 2px 6px; border-radius: 4px; font-family: 'Consolas', monospace; }
        .status { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; }
        .online { background: #28a745; }
        .card { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <h1>🦬 YAKMESH Self-Contained Node</h1>
    <p>Your complete Yakmesh stack is running.</p>
    
    <div class="card">
        <h2>Services</h2>
        <p><span class="status online"></span><strong>Web Server:</strong> <a href="http://localhost:8080">http://localhost:8080</a></p>
        <p><span class="status online"></span><strong>Content API:</strong> <a href="http://localhost:3000/content">http://localhost:3000/content</a></p>
        <p><span class="status online"></span><strong>PHP:</strong> <a href="http://localhost:8080/info.php">http://localhost:8080/info.php</a></p>
        <p><span class="status online"></span><strong>Mesh P2P:</strong> <code>ws://localhost:9001</code></p>
    </div>
    
    <div class="card">
        <h2>Content API</h2>
        <ul>
            <li><code>GET /content</code> - List all content</li>
            <li><code>GET /content/:hash</code> - Get content by hash</li>
            <li><code>POST /content</code> - Store new content</li>
        </ul>
    </div>
    
    <div class="card">
        <h2>Bundled Software</h2>
        <ul>
            <li>Node.js 20 LTS</li>
            <li>PHP 8.3</li>
            <li>Caddy 2.8</li>
            <li>7-Zip CLI</li>
        </ul>
    </div>
    
    <p><a href="https://yakmesh.dev">yakmesh.dev</a> | <a href="https://github.com/yakmesh/yakmesh">GitHub</a></p>
</body>
</html>
"@ | Out-File -FilePath $indexPath -Encoding utf8
}

# Create PHP info file
$phpInfoPath = Join-Path $ScriptDir "htdocs\info.php"
if (-not (Test-Path $phpInfoPath)) {
    @"
<?php
phpinfo();
"@ | Out-File -FilePath $phpInfoPath -Encoding utf8
}

# Install node_modules using bundled Node if needed
if (-not (Test-Path "node_modules")) {
    Write-Host "[INFO] Installing Node.js dependencies..." -ForegroundColor Yellow
    $env:PATH = "$(Split-Path $nodeBin);$env:PATH"
    & $nodeBin (Get-Command npm).Source install 2>&1 | Out-Null
}

Write-Host ""
Write-Host "[INFO] Starting services..." -ForegroundColor Yellow
Write-Host ""

# Start PHP FastCGI
$phpJob = Start-Process -FilePath $phpBin -ArgumentList "-b", "127.0.0.1:9000", "-c", $phpIni -WindowStyle Hidden -PassThru
Write-Host "  ✓ PHP FastCGI started (PID: $($phpJob.Id))" -ForegroundColor Green

# Start Yakmesh node using bundled Node
$env:YAKMESH_CONFIG = Join-Path $ScriptDir "config\yakmesh.config.js"
$meshJob = Start-Process -FilePath $nodeBin -ArgumentList "server/index.js" -WorkingDirectory $ScriptDir -WindowStyle Hidden -PassThru
Write-Host "  ✓ Mesh Node started (PID: $($meshJob.Id))" -ForegroundColor Green

Start-Sleep -Seconds 2

# Start Caddy
$caddyfile = Join-Path $ScriptDir "config\Caddyfile"
$caddyJob = Start-Process -FilePath $caddyBin -ArgumentList "run", "--config", $caddyfile -WorkingDirectory $ScriptDir -WindowStyle Hidden -PassThru
Write-Host "  ✓ Caddy started (PID: $($caddyJob.Id))" -ForegroundColor Green

Write-Host ""
Write-Host "  ========================================" -ForegroundColor Green
Write-Host "  All services running!" -ForegroundColor Green
Write-Host "  ========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Web Server:    http://localhost:8080" -ForegroundColor Cyan
Write-Host "  PHP Info:      http://localhost:8080/info.php" -ForegroundColor Cyan
Write-Host "  Content API:   http://localhost:3000/content" -ForegroundColor Cyan
Write-Host "  Mesh P2P:      ws://localhost:9001" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Press any key to stop all services..." -ForegroundColor Yellow
Write-Host ""

# Save PIDs
@{
    php = $phpJob.Id
    mesh = $meshJob.Id
    caddy = $caddyJob.Id
    startTime = Get-Date -Format "o"
} | ConvertTo-Json | Out-File (Join-Path $ScriptDir "data\.pids.json")

# Wait for keypress
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Write-Host ""
Write-Host "[INFO] Shutting down..." -ForegroundColor Yellow

# Stop all processes
Stop-Process -Id $caddyJob.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $meshJob.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $phpJob.Id -Force -ErrorAction SilentlyContinue

# Clean up any orphans
Get-Process -Name "caddy", "php-cgi", "node" -ErrorAction SilentlyContinue | 
    Where-Object { $_.Path -like "*yakmesh*" } | 
    Stop-Process -Force -ErrorAction SilentlyContinue

Remove-Item (Join-Path $ScriptDir "data\.pids.json") -ErrorAction SilentlyContinue

Write-Host "[OK] All services stopped" -ForegroundColor Green
