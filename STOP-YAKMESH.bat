@echo off
rem Stop a hidden/silent YakMesh node started by start-yakmesh-silent.vbs
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | Where-Object { $_.CommandLine -match 'server[\\/]index\.js' } | ForEach-Object { Write-Host ('Stopping PID ' + $_.ProcessId); Stop-Process -Id $_.ProcessId -Force }"
timeout /t 2 >nul
