<#
.SYNOPSIS
    Stop YAKMESH Self-Contained Node
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pidsFile = Join-Path $ScriptDir "data\.pids.json"

Write-Host ""
Write-Host "[INFO] Stopping YAKMESH services..." -ForegroundColor Yellow

# Load PIDs if available
if (Test-Path $pidsFile) {
    $pids = Get-Content $pidsFile | ConvertFrom-Json
    
    if ($pids.caddy) { Stop-Process -Id $pids.caddy -Force -ErrorAction SilentlyContinue }
    if ($pids.mesh) { Stop-Process -Id $pids.mesh -Force -ErrorAction SilentlyContinue }
    if ($pids.php) { Stop-Process -Id $pids.php -Force -ErrorAction SilentlyContinue }
    
    Remove-Item $pidsFile -ErrorAction SilentlyContinue
}

# Also stop by name in case PIDs are stale
Get-Process -Name "caddy" -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name "php-cgi" -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -like "*yakmesh*"
} | Stop-Process -Force

Write-Host "[OK] Caddy stopped" -ForegroundColor Green
Write-Host "[OK] PHP stopped" -ForegroundColor Green
Write-Host "[OK] Mesh node stopped" -ForegroundColor Green
Write-Host ""
Write-Host "[OK] All services stopped" -ForegroundColor Green
Write-Host ""
