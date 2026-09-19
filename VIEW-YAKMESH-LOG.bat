@echo off
rem Tail the silent-mode node log (Ctrl+C to stop watching, node keeps running)
cd /d "%~dp0"
powershell -NoProfile -Command "Get-Content yakmesh-node.log -Wait -Tail 40"
