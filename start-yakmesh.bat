@echo off
REM Start YAKMESH Node — works with or without PM2
REM NOTE: never copy yakmesh.config.production.js over yakmesh.config.js —
REM config.js is oracle-hashed; overwriting it changes the network id
REM and drops the shipped LAN bootstrap seeds.
REM Run this from the yakmesh-node directory

echo Starting YAKMESH Node...

if not exist "logs" mkdir logs
if not exist "data" mkdir data

if not exist "node_modules" (
    echo Installing dependencies...
    call npm install --omit=dev
)

REM PM2 if available (auto-restart), else plain node.
REM Both paths launch through scripts\yakmesh-run.js — the supervisor
REM applies staged ACT package swaps, respawns the node, and starts
REM yakos-pq-bridge automatically when one is present but not running.
where pm2 >nul 2>nul
if %ERRORLEVEL%==0 (
    pm2 start ecosystem.config.json
    echo.
    echo YAKMESH Node started under PM2. Status: pm2 status ^| Logs: pm2 logs yakmesh
) else (
    echo PM2 not found — starting node under the supervisor in this window.
    echo Ctrl+C to stop. For headless start use start-yakmesh-silent.vbs
    echo.
    node scripts\yakmesh-run.js
)
