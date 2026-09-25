@echo off
REM ============================================================
REM START-YAKMESH — canonical launcher (REVIVE-style clean slate)
REM   1. Kills stale yakmesh node / supervisor / pq-bridge processes
REM   2. Provisions the hardware-bound keystore if missing
REM      (pq-bridge exits 'os error 3' without it)
REM   3. Starts the pq-bridge if not already listening on :9995
REM   4. Launches the supervisor — the ONLY supported node entry
REM      (applies staged ACT swaps, manages the bridge, respawns)
REM NOTE: never copy yakmesh.config.production.js over yakmesh.config.js —
REM config.js is oracle-hashed; overwriting it changes the network id.
REM Run from the yakmesh runtime root. Keep this window open.
REM ============================================================
cd /d %~dp0

echo [start] stopping stale yakmesh / bridge processes...
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'yakmesh-run\.js|server[\\/]index\.js' } | ForEach-Object { Write-Host ('  kill ' + $_.ProcessId + ' ' + $_.Name); Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'yakos-pq-bridge' } | ForEach-Object { Write-Host ('  kill ' + $_.ProcessId + ' ' + $_.Name); Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
timeout /t 2 >nul

if not exist "logs" mkdir logs
if not exist "data" mkdir data

if not exist "node_modules" (
    echo [start] installing dependencies...
    call npm install --omit=dev
)

REM Keystore — hardware-bound identity store. The attestation bundle ships
REM inside this package; resolve whichever name variant is present.
set "KS_EXE=%~dp0yakos-keystore.exe"
if not exist "%KS_EXE%" for %%F in ("%~dp0yakos-keystore-*.exe") do set "KS_EXE=%%~fF"
set "BR_EXE=%~dp0yakos-pq-bridge.exe"
if not exist "%BR_EXE%" for %%F in ("%~dp0yakos-pq-bridge-*.exe") do set "BR_EXE=%%~fF"

set "KS_DIR=%LOCALAPPDATA%\yakos"
set "YAKOS_KEYSTORE_PATH=%KS_DIR%\keystore.json"

if exist "%YAKOS_KEYSTORE_PATH%" (
    echo [start] keystore present: %YAKOS_KEYSTORE_PATH%
) else if exist "C:\ProgramData\yakos\keystore.json" (
    echo [start] keystore present: C:\ProgramData\yakos\keystore.json
) else (
    echo [start] keystore missing - initializing hardware-bound store...
    if not exist "%KS_DIR%" mkdir "%KS_DIR%"
    if exist "%KS_EXE%" (
        "%KS_EXE%" --path "%YAKOS_KEYSTORE_PATH%" init
    ) else (
        echo [start] WARNING: no yakos-keystore binary in this package
    )
    if exist "%YAKOS_KEYSTORE_PATH%" (
        echo [start] keystore created
    ) else (
        echo [start] WARNING: keystore init failed - bridge will report 'os error 3'
        echo [start]          and canon attestation stays down. Continuing anyway.
    )
)

REM Bridge check — supervisor adopts a healthy bridge or spawns its own,
REM but a cold pre-start makes canon signing available at first heartbeat.
powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 'http://127.0.0.1:9995/health').StatusCode -eq 200 } catch { exit 1 }" >nul 2>nul
if %ERRORLEVEL%==0 (
    echo [start] pq-bridge already healthy on :9995
) else if exist "%BR_EXE%" (
    echo [start] starting pq-bridge on 127.0.0.1:9995 ...
    start "yakos-pq-bridge" /min "%BR_EXE%"
    timeout /t 2 >nul
) else (
    echo [start] WARNING: no yakos-pq-bridge binary in this package - attestation idle
)

if exist data\pending-update\package.zip (
    echo [start] staged ACT package present - supervisor applies it on launch
)

echo [start] launching supervisor (relay + seva + attestation are on by default)
echo [start] console output tees to logs\yakmesh-run-console.log
node scripts\yakmesh-run.js 2>&1 | powershell -NoProfile -Command "$input | Tee-Object -FilePath 'logs\yakmesh-run-console.log'"
