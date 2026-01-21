# YakBot Deployment Package

Discord community bot for YAKMESH™.

## Quick Deploy

1. **Extract** this package to your server
2. **Configure** environment variables in `.env`
3. **Install** dependencies: `npm install`
4. **Register** Discord commands: `npm run register`
5. **Start** the bot: `npm start`

## Environment Variables

Create a `.env` file with:

```env
# Discord Bot Token (required)
# Get from: https://discord.com/developers/applications
DISCORD_TOKEN=your_discord_bot_token

# Gemini API Key (optional, enables /ask command)
# Get from: https://makersuite.google.com/app/apikey
GEMINI_API_KEY=your_gemini_api_key
```

## Discord Bot Setup

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a new application
3. Go to **Bot** section, click "Add Bot"
4. Copy the token to your `.env` file
5. Enable these **Privileged Gateway Intents**:
   - MESSAGE CONTENT INTENT
   - SERVER MEMBERS INTENT
6. Go to **OAuth2 > URL Generator**:
   - Scopes: `bot`, `applications.commands`
   - Permissions: `Send Messages`, `Embed Links`, `Read Message History`
7. Use the generated URL to invite the bot to your server
8. Run `npm run register` to register slash commands

## Commands

| Command | Description |
|---------|-------------|
| `/status` | Show YAKMESH version and project stats |
| `/nodes` | Check official node health status |
| `/docs [topic]` | Get documentation links |
| `/changelog` | View recent changes |
| `/install` | Quick installation guide |
| `/ask <question>` | Ask YakBot about YAKMESH (AI-powered) |
| `/links` | All social and resource links |
| `/faq` | Frequently asked questions |
| `/ping` | Check bot latency |
| `/botstats` | View bot performance metrics |
| `/help` | Show all commands |

## Running with PM2

```bash
# Install PM2 globally
npm install -g pm2

# Start the bot
pm2 start index.js --name yakbot

# Save process list
pm2 save

# Setup startup script
pm2 startup
```

## Running as Windows Service

Use [nssm](https://nssm.cc/) to run as a Windows service:

```powershell
# Install as service
nssm install yakbot "C:\path\to\node.exe" "C:\path\to\yakbot\index.js"

# Start the service
nssm start yakbot
```

## Files

- `index.js` - Main bot code
- `register-commands.js` - Discord command registration
- `package.json` - Dependencies
- `.env.example` - Environment template

## Version

YakBot v2.3.0 - Updated for YAKMESH v2.3.0

## Support

- Discord: https://discord.gg/8mSPfbJB8N
- GitHub: https://github.com/yakmesh/yakmesh
- Docs: https://yakmesh.dev/docs

---
YAKMESH™ is a trademark of PeerQuanta
