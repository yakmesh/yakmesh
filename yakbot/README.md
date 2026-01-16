# 🤖 YakBot - YAKMESH Discord Bot

Interactive Discord bot that provides community support for YAKMESH users.

## Features

- **📊 `/status`** - Show current version and project stats
- **📚 `/docs [topic]`** - Get documentation links for specific topics
- **📋 `/changelog`** - View recent changes
- **📦 `/install`** - Quick installation instructions
- **❓ `/ask [question]`** - Ask questions about YAKMESH (AI-powered)
- **🔗 `/links`** - All social and resource links
- **🏓 `/ping`** - Check bot latency

Plus **automatic release announcements** via GitHub Actions!

## Quick Setup (5 minutes)

### 1. Create Discord Application

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click **"New Application"** → Name it **"YakBot"**
3. Go to **"Bot"** tab → Click **"Add Bot"**
4. Under Token, click **"Reset Token"** → Copy the token (save it!)
5. Enable these **Privileged Gateway Intents**:
   - ✅ MESSAGE CONTENT INTENT
6. Go to **"OAuth2"** → **"URL Generator"**:
   - Scopes: `bot`, `applications.commands`
   - Bot Permissions: `Send Messages`, `Embed Links`, `Use Slash Commands`
7. Copy the generated URL and open it to invite the bot to your server

### 2. Configure Bot

Create `.env` file:

```env
DISCORD_TOKEN=your_bot_token_here
DISCORD_CLIENT_ID=your_application_id
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

**Where to find these:**
- `DISCORD_TOKEN` - Bot tab → Token (step 4 above)
- `DISCORD_CLIENT_ID` - General Information → Application ID
- `DISCORD_WEBHOOK_URL` - Server Settings → Integrations → Webhooks

### 3. Install & Run

```bash
cd yakbot
npm install
node register-commands.js  # One-time: register slash commands
npm start                   # Start the bot
```

## Project Structure

```
yakbot/
├── index.js              # Main bot logic
├── register-commands.js  # Slash command registration
├── package.json
├── .env.example         # Example config
└── README.md            # This file
```

## GitHub Actions Integration

The workflow at `.github/workflows/discord-release.yml` automatically posts to Discord when you:
- Create a GitHub Release
- Push a version tag (v*)

**Setup**: Add `DISCORD_WEBHOOK_URL` to your repo's secrets:
1. GitHub repo → Settings → Secrets → Actions
2. New secret: `DISCORD_WEBHOOK_URL` with your webhook URL

## Deployment Options

### Option A: Run Locally
```bash
npm start
# Keep terminal open or use PM2/screen
```

### Option B: PM2 (Recommended for servers)
```bash
npm install -g pm2
pm2 start index.js --name yakbot
pm2 save
pm2 startup  # Auto-start on reboot
```

### Option C: Docker
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
CMD ["node", "index.js"]
```

### Option D: Cloud Hosting
- **Railway.app** - Free tier available
- **Fly.io** - Free tier available
- **DigitalOcean** - $5/mo droplet
- **Heroku** - Eco dynos $5/mo

## Commands Reference

| Command | Description | Example |
|---------|-------------|---------|
| `/status` | Current version info | `/status` |
| `/docs` | Documentation links | `/docs topic:annex` |
| `/changelog` | Recent changes | `/changelog` |
| `/install` | Installation help | `/install` |
| `/ask` | Ask a question | `/ask How does gossip work?` |
| `/links` | All project links | `/links` |
| `/ping` | Bot latency | `/ping` |

## Extending YakBot

To add new commands:

1. Add command definition in `register-commands.js`
2. Add handler in `index.js` switch statement
3. Re-run `node register-commands.js`

Example:
```javascript
// In register-commands.js
new SlashCommandBuilder()
  .setName('example')
  .setDescription('Example command'),

// In index.js handleSlashCommand()
case 'example':
  await interaction.reply('Hello!');
  break;
```

## Troubleshooting

**Commands not appearing?**
- Global commands take up to 1 hour to propagate
- For instant testing, use guild-specific commands
- Restart Discord (Ctrl+R)

**Bot offline?**
- Check `DISCORD_TOKEN` is correct
- Ensure bot has been invited to server
- Check for errors in console

**Webhook not posting?**
- Verify webhook URL in GitHub Secrets
- Check webhook hasn't been deleted in Discord

## Support

- 💬 [Discord Server](https://discord.gg/j3hj8CQksP)
- 🐙 [GitHub Issues](https://github.com/nicholascormier/yakmesh/issues)
- 📧 hello@yakmesh.com

---

Built with ❤️ for the YAKMESH community
