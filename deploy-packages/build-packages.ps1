<#
.SYNOPSIS
    Build YAKMESH deployment packages

.DESCRIPTION
    Downloads all required binaries and creates:
    - yakmesh-minimal-win-x64.zip (lightweight, downloads on first run)
    - yakmesh-full-win-x64.zip (self-contained, everything bundled)

.PARAMETER Target
    Which package to build: 'minimal', 'full', or 'all' (default)
#>

param(
    [ValidateSet('minimal', 'full', 'all')]
    [string]$Target = 'all'
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $ScriptDir "build"
$DownloadDir = Join-Path $ScriptDir "downloads"

# Version configuration
$Versions = @{
    Caddy = "2.8.4"
    PHP = "8.3.14"
    Node = "20.11.0"
    SevenZip = "2401"
}

$Downloads = @{
    Caddy = "https://github.com/caddyserver/caddy/releases/download/v$($Versions.Caddy)/caddy_$($Versions.Caddy)_windows_amd64.zip"
    PHP = "https://windows.php.net/downloads/releases/php-$($Versions.PHP)-nts-Win32-vs16-x64.zip"
    Node = "https://nodejs.org/dist/v$($Versions.Node)/node-v$($Versions.Node)-win-x64.zip"
    SevenZip = "https://www.7-zip.org/a/7z$($Versions.SevenZip)-x64.exe"
}

function Download-File {
    param([string]$Url, [string]$OutFile)
    
    if (Test-Path $OutFile) {
        Write-Host "  [CACHED] $(Split-Path $OutFile -Leaf)" -ForegroundColor Gray
        return
    }
    
    Write-Host "  [DOWNLOAD] $Url" -ForegroundColor Cyan
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
}

function Build-Minimal {
    Write-Host ""
    Write-Host "Building MINIMAL package..." -ForegroundColor Green
    
    $minimalDir = Join-Path $BuildDir "yakmesh-minimal"
    
    # Clean and create
    if (Test-Path $minimalDir) { Remove-Item $minimalDir -Recurse -Force }
    New-Item -ItemType Directory -Path $minimalDir -Force | Out-Null
    
    # Copy yakmesh-node source (excluding dev files)
    $yakmeshSrc = Join-Path $ScriptDir "..\yakmesh-node"
    $excludes = @('.git', 'node_modules', 'test-*', '*.test.js', 'data', 'database', 'logs')
    
    Write-Host "  Copying Yakmesh source..." -ForegroundColor Yellow
    Get-ChildItem $yakmeshSrc -Exclude $excludes | Copy-Item -Destination $minimalDir -Recurse -Force
    
    # Copy minimal config
    $minimalCfg = Join-Path $ScriptDir "yakmesh-minimal"
    Copy-Item (Join-Path $minimalCfg "config") -Destination $minimalDir -Recurse -Force
    Copy-Item (Join-Path $minimalCfg "*.ps1") -Destination $minimalDir -Force
    Copy-Item (Join-Path $minimalCfg "README.md") -Destination $minimalDir -Force
    
    # Create empty directories
    @("bin", "htdocs", "data", "logs") | ForEach-Object {
        New-Item -ItemType Directory -Path (Join-Path $minimalDir $_) -Force | Out-Null
    }
    
    # Create zip
    $zipPath = Join-Path $BuildDir "yakmesh-minimal-win-x64.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath }
    
    Write-Host "  Creating archive..." -ForegroundColor Yellow
    Compress-Archive -Path "$minimalDir\*" -DestinationPath $zipPath -CompressionLevel Optimal
    
    $size = (Get-Item $zipPath).Length / 1MB
    Write-Host "  [OK] yakmesh-minimal-win-x64.zip ($([math]::Round($size, 2)) MB)" -ForegroundColor Green
}

function Build-Full {
    Write-Host ""
    Write-Host "Building FULL (self-contained) package..." -ForegroundColor Green
    
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
    
    # Note: 7-Zip is an installer, we'd need to extract it differently
    # For now, skip 7z or use portable version
    
    # Copy yakmesh-node source
    $yakmeshSrc = Join-Path $ScriptDir "..\yakmesh-node"
    $excludes = @('.git', 'node_modules', 'test-*', '*.test.js', 'data', 'database', 'logs')
    
    Write-Host "  Copying Yakmesh source..." -ForegroundColor Yellow
    Get-ChildItem $yakmeshSrc -Exclude $excludes | Copy-Item -Destination $fullDir -Recurse -Force
    
    # Extract Caddy
    Write-Host "  Extracting Caddy..." -ForegroundColor Yellow
    $binDir = Join-Path $fullDir "bin"
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
    Expand-Archive -Path $caddyZip -DestinationPath $binDir -Force
    
    # Extract PHP
    Write-Host "  Extracting PHP..." -ForegroundColor Yellow
    $phpDir = Join-Path $binDir "php"
    New-Item -ItemType Directory -Path $phpDir -Force | Out-Null
    Expand-Archive -Path $phpZip -DestinationPath $phpDir -Force
    
    # Extract Node
    Write-Host "  Extracting Node.js..." -ForegroundColor Yellow
    $nodeTmpDir = Join-Path $DownloadDir "node-tmp"
    Expand-Archive -Path $nodeZip -DestinationPath $nodeTmpDir -Force
    $nodeExtracted = Get-ChildItem $nodeTmpDir | Select-Object -First 1
    $nodeDir = Join-Path $binDir "node"
    Move-Item $nodeExtracted.FullName $nodeDir -Force
    Remove-Item $nodeTmpDir -Recurse -Force
    
    # Copy full config
    $fullCfg = Join-Path $ScriptDir "yakmesh-full"
    Copy-Item (Join-Path $fullCfg "config") -Destination $fullDir -Recurse -Force
    Copy-Item (Join-Path $fullCfg "*.ps1") -Destination $fullDir -Force
    Copy-Item (Join-Path $fullCfg "README.md") -Destination $fullDir -Force
    
    # Create directories
    @("htdocs", "data", "data\content", "logs") | ForEach-Object {
        New-Item -ItemType Directory -Path (Join-Path $fullDir $_) -Force | Out-Null
    }
    
    # Create PHP info file
    "<?php phpinfo();" | Out-File -FilePath (Join-Path $fullDir "htdocs\info.php") -Encoding utf8
    
    # Create zip
    $zipPath = Join-Path $BuildDir "yakmesh-full-win-x64.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath }
    
    Write-Host "  Creating archive..." -ForegroundColor Yellow
    Compress-Archive -Path "$fullDir\*" -DestinationPath $zipPath -CompressionLevel Optimal
    
    $size = (Get-Item $zipPath).Length / 1MB
    Write-Host "  [OK] yakmesh-full-win-x64.zip ($([math]::Round($size, 2)) MB)" -ForegroundColor Green
}

# Main
Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  YAKMESH Package Builder" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Versions:" -ForegroundColor Yellow
Write-Host "  Caddy:    $($Versions.Caddy)"
Write-Host "  PHP:      $($Versions.PHP)"
Write-Host "  Node.js:  $($Versions.Node)"
Write-Host ""

# Create build directory
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null

switch ($Target) {
    'minimal' { Build-Minimal }
    'full' { Build-Full }
    'all' {
        Build-Minimal
        Build-Full
    }
}

Write-Host ""
Write-Host "=====================================" -ForegroundColor Green
Write-Host "  Build Complete!" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green
Write-Host ""
Write-Host "Packages created in: $BuildDir" -ForegroundColor Cyan
Get-ChildItem $BuildDir -Filter "*.zip" | ForEach-Object {
    $size = $_.Length / 1MB
    Write-Host "  - $($_.Name) ($([math]::Round($size, 2)) MB)"
}
Write-Host ""
