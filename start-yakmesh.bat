@echo off
REM Start YAKMESH Node with PM2
REM Run this from the yakmesh-node directory

echo Starting YAKMESH Node...

REM Copy production config to main config
copy /Y yakmesh.config.production.js yakmesh.config.js

REM Create logs directory if needed
if not exist "logs" mkdir logs
if not exist "data" mkdir data

REM Install dependencies if needed
if not exist "node_modules" (
    echo Installing dependencies...
    call npm install --production
)

REM Start with PM2
pm2 start ecosystem.config.json

echo.
echo YAKMESH Node started! Check status with: pm2 status
echo View logs with: pm2 logs yakmesh-node
