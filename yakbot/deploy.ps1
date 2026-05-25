# PowerShell Deploy Script for YakBot to Hostinger
$ErrorActionPreference = "Stop"

$HOSTINGER_IP = "156.67.75.34"
$HOSTINGER_USER = "u170268362"
$HOSTINGER_PORT = "65002"
$DEST_DIR = "~/yakbot"

Write-Host "Zipping bot files..."
if (Test-Path "yakbot-deploy.zip") {
    Remove-Item "yakbot-deploy.zip" -Force
}

Compress-Archive -Path "index.js", "package.json", "register-commands.js", ".env", "utils*" -DestinationPath yakbot-deploy.zip -Force

Write-Host "Uploading to Hostinger ($HOSTINGER_USER@$HOSTINGER_IP)..."
scp -P $HOSTINGER_PORT yakbot-deploy.zip ${HOSTINGER_USER}@${HOSTINGER_IP}:${DEST_DIR}/
scp -P $HOSTINGER_PORT ../knowledge-base.js ${HOSTINGER_USER}@${HOSTINGER_IP}:~/knowledge-base.js

Write-Host "Restarting script via SSH..."
ssh -p $HOSTINGER_PORT ${HOSTINGER_USER}@${HOSTINGER_IP} "cd $DEST_DIR && unzip -o yakbot-deploy.zip && npm install --production && pm2 restart yakbot"

Write-Host "Deploy completed successfully!"
