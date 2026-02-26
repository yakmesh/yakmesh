@echo off
:: ============================================================================
:: YAKMESH Launcher - Quick Start
:: Opens dashboard in browser and starts the node
:: ============================================================================

title YAKMESH Node

:: Find Node.js
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js not found in PATH
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

:: Get script directory
set SCRIPT_DIR=%~dp0
set NODE_DIR=%SCRIPT_DIR%..

:: Check if server exists
if not exist "%NODE_DIR%\server\index.js" (
    echo [ERROR] server/index.js not found
    echo Expected at: %NODE_DIR%\server\index.js
    pause
    exit /b 1
)

:: Read port from config or use default
set HTTP_PORT=3789
if defined YAKMESH_HTTP_PORT set HTTP_PORT=%YAKMESH_HTTP_PORT%

echo.
echo   ========================================================================
echo.
echo    YY   YY   AA   KK  KK MM   MM EEEE  SSSS HH   HH
echo     YY YY   AAAA  KK KK  MMM MMM EE   SS    HH   HH
echo      YYY   AA  AA KKKK   MM M MM EEE   SSS  HHHHHHH
echo      YY    AAAAAA KK KK  MM   MM EE      SS HH   HH
echo      YY    AA  AA KK  KK MM   MM EEEE SSSS  HH   HH
echo.
echo          Post-Quantum Secure P2P Mesh Network
echo.
echo   ========================================================================
echo.
echo   [*] Starting YAKMESH node...
echo   [*] Dashboard: http://localhost:%HTTP_PORT%/dashboard
echo   [*] Press Ctrl+C to stop
echo.

:: Open dashboard in browser after short delay
start "" cmd /c "ping -n 3 127.0.0.1 >nul && start http://localhost:%HTTP_PORT%/dashboard"

:: Change to node directory and start
cd /d "%NODE_DIR%"
node server/index.js

:: If we get here, node exited
echo.
echo   [!] Node stopped.
pause
