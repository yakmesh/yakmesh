<#
.SYNOPSIS
    Build YakBot DEV deployment package (includes credentials)
.DESCRIPTION
    Creates a ready-to-deploy YakBot package with .env included.
    For internal/dev use only - DO NOT distribute publicly!
.EXAMPLE
    .\build-yakbot-dev.ps1
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceDir = Split-Path -Parent $ScriptDir
$YakbotSource = Join-Path $SourceDir "yakbot"
$BuildDir = Join-Path $ScriptDir "build"

Write-Host ""
Write-Host "=============================================" -ForegroundColor Magenta
Write-Host "  YakBot DEV Deployment Package Builder" -ForegroundColor Magenta
Write-Host "  [INCLUDES .env - DO NOT DISTRIBUTE]" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Magenta
Write-Host ""

if (-not (Test-Path $YakbotSource)) {
    Write-Host "[ERROR] YakBot source not found at: $YakbotSource" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
}

$YakbotBuild = Join-Path $BuildDir "yakbot-dev"

if (Test-Path $YakbotBuild) {
    Write-Host "Cleaning previous build..." -ForegroundColor Yellow
    Remove-Item $YakbotBuild -Recurse -Force
}

New-Item -ItemType Directory -Path $YakbotBuild -Force | Out-Null
Write-Host "Building YakBot DEV package..." -ForegroundColor Green

$FilesToCopy = @('index.js','register-commands.js','package.json','package-lock.json','.env','.env.example','.gitignore','README.md','start-yakbot.bat')

foreach ($file in $FilesToCopy) {
    $srcPath = Join-Path $YakbotSource $file
    if (Test-Path $srcPath) {
        Copy-Item $srcPath -Destination $YakbotBuild -Force
        Write-Host "  [COPY] $file" -ForegroundColor Gray
    }
}

$UtilsSource = Join-Path $YakbotSource "utils"
$UtilsDest = Join-Path $YakbotBuild "utils"
if (Test-Path $UtilsSource) {
    New-Item -ItemType Directory -Path $UtilsDest -Force | Out-Null
    Copy-Item "$UtilsSource\*" -Destination $UtilsDest -Recurse -Force
    Write-Host "  [COPY] utils/" -ForegroundColor Gray
}

# PM2 ecosystem (use .cjs for CommonJS in ESM project)
$eco = "module.exports = { apps: [{ name: 'yakbot', script: 'index.js', instances: 1, autorestart: true, watch: false, max_memory_restart: '200M', env: { NODE_ENV: 'production' } }] };"
$eco | Out-File -FilePath "$YakbotBuild\ecosystem.config.cjs" -Encoding UTF8
Write-Host "  [CREATE] ecosystem.config.cjs" -ForegroundColor Cyan

# Deploy script
$deploy = "@echo off`r`necho Installing dependencies...`r`ncall npm install --production`r`necho Registering commands...`r`ncall node register-commands.js`r`necho Starting with PM2...`r`ncall npx pm2 start ecosystem.config.cjs`r`ncall npx pm2 save`r`necho Done! Use 'npx pm2 logs yakbot' to view logs`r`npause"
$deploy | Out-File -FilePath "$YakbotBuild\deploy.bat" -Encoding ASCII
Write-Host "  [CREATE] deploy.bat" -ForegroundColor Cyan

$files = Get-ChildItem $YakbotBuild -Recurse -File
$count = $files.Count
$sizeKB = [math]::Round(($files | Measure-Object Length -Sum).Sum / 1KB, 1)
Write-Host "`nPackage: $count files ($sizeKB KB)" -ForegroundColor Cyan

$ZipPath = Join-Path $BuildDir "yakbot-dev.zip"
if (Test-Path $ZipPath) { Remove-Item $ZipPath }
Compress-Archive -Path "$YakbotBuild\*" -DestinationPath $ZipPath -CompressionLevel Optimal

Write-Host "[OK] yakbot-dev.zip created" -ForegroundColor Green
Write-Host "Location: $ZipPath" -ForegroundColor Gray
Write-Host "`nTo deploy: copy folder to server, run deploy.bat" -ForegroundColor Yellow
