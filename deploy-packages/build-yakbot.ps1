<#
.SYNOPSIS
    Build YakBot deployment package

.DESCRIPTION
    Creates a standalone YakBot deployment package with all necessary files.

.EXAMPLE
    .\build-yakbot.ps1
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceDir = Split-Path -Parent $ScriptDir  # yakmesh-node directory
$YakbotSource = Join-Path $SourceDir "yakbot"
$BuildDir = Join-Path $ScriptDir "build"

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  YakBot Deployment Package Builder" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Check source exists
if (-not (Test-Path $YakbotSource)) {
    Write-Host "[ERROR] YakBot source not found at: $YakbotSource" -ForegroundColor Red
    exit 1
}

# Create build directory
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
}

$YakbotBuild = Join-Path $BuildDir "yakbot"

# Clean previous build
if (Test-Path $YakbotBuild) {
    Write-Host "Cleaning previous build..." -ForegroundColor Yellow
    Remove-Item $YakbotBuild -Recurse -Force
}

New-Item -ItemType Directory -Path $YakbotBuild -Force | Out-Null

Write-Host "Building YakBot package..." -ForegroundColor Green
Write-Host ""

# Files to copy
$FilesToCopy = @(
    'index.js',
    'register-commands.js',
    'package.json',
    'package-lock.json',
    '.env.example',
    '.gitignore',
    'README.md',
    'start-yakbot.bat'
)

foreach ($file in $FilesToCopy) {
    $srcPath = Join-Path $YakbotSource $file
    if (Test-Path $srcPath) {
        Copy-Item $srcPath -Destination $YakbotBuild -Force
        Write-Host "  [COPY] $file" -ForegroundColor Gray
    } else {
        Write-Host "  [SKIP] $file (not found)" -ForegroundColor Yellow
    }
}

# Copy the utils directory (yakbot has its own self-contained logger)
$UtilsSource = Join-Path $YakbotSource "utils"
$UtilsDest = Join-Path $YakbotBuild "utils"
if (Test-Path $UtilsSource) {
    New-Item -ItemType Directory -Path $UtilsDest -Force | Out-Null
    Copy-Item "$UtilsSource\*" -Destination $UtilsDest -Recurse -Force
    Write-Host "  [COPY] utils/" -ForegroundColor Gray
}

# Copy README from deploy-packages/yakbot
$DeployReadme = Join-Path $ScriptDir "yakbot\README.md"
if (Test-Path $DeployReadme) {
    Copy-Item $DeployReadme -Destination $YakbotBuild -Force
    Write-Host "  [COPY] README.md (deployment version)" -ForegroundColor Gray
}

# Get stats
$files = Get-ChildItem $YakbotBuild -Recurse -File -ErrorAction SilentlyContinue
$count = $files.Count
$size = ($files | Measure-Object Length -Sum).Sum
$sizeKB = [math]::Round($size / 1KB, 1)

Write-Host ""
Write-Host "Package contents: $count files ($sizeKB KB)" -ForegroundColor Cyan

# Create zip
$ZipPath = Join-Path $BuildDir "yakbot.zip"
if (Test-Path $ZipPath) { Remove-Item $ZipPath }

Write-Host "Creating archive..." -ForegroundColor Yellow
Compress-Archive -Path "$YakbotBuild\*" -DestinationPath $ZipPath -CompressionLevel Optimal

$zipSize = [math]::Round((Get-Item $ZipPath).Length / 1KB, 1)
Write-Host ""
Write-Host "[OK] yakbot.zip created ($zipSize KB)" -ForegroundColor Green
Write-Host "     Location: $ZipPath" -ForegroundColor Gray
Write-Host ""

# Instructions
Write-Host "To deploy:" -ForegroundColor Cyan
Write-Host "  1. Extract yakbot.zip to server" -ForegroundColor Gray
Write-Host "  2. Create .env with DISCORD_TOKEN" -ForegroundColor Gray
Write-Host "  3. Run: npm install" -ForegroundColor Gray
Write-Host "  4. Run: npm run register" -ForegroundColor Gray
Write-Host "  5. Run: npm start" -ForegroundColor Gray
Write-Host ""
