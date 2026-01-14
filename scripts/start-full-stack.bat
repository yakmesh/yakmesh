@echo off
:: Yakmesh Full Stack Launcher (Windows)

echo ====================================
echo    YAKMESH - Self-Hosting Stack
echo ====================================
echo.

echo [1/2] Starting Caddy web server...
start /B bin\caddy.exe run --config Caddyfile

echo [2/2] Starting Yakmesh mesh node...
start /B node server\index.js

echo.
echo Services running:
echo   Web:  http://localhost:8080
echo   Mesh: ws://localhost:9001
echo   Dashboard: http://localhost:3000
echo.
echo Press any key to stop...
pause >nul

taskkill /F /IM caddy.exe 2>nul
taskkill /F /IM node.exe 2>nul