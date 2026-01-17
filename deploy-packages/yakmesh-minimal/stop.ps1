<#
.SYNOPSIS
    Stop YAKMESH Minimal Node
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pidsFile = Join-Path $ScriptDir "data\.pids.json"

Write-Host ""
Write-Host "[INFO] Stopping YAKMESH services..." -ForegroundColor Yellow

# Stop Caddy
Get-Process -Name "caddy" -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Host "[OK] Caddy stopped" -ForegroundColor Green

# Stop Node processes for this directory
Get-Process -Name "node" -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -like "*yakmesh*"
} | Stop-Process -Force
Write-Host "[OK] Node processes stopped" -ForegroundColor Green

# Clean up PID file
if (Test-Path $pidsFile) {
    Remove-Item $pidsFile
}

Write-Host ""
Write-Host "[OK] All services stopped" -ForegroundColor Green
Write-Host ""
