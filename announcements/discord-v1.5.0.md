# Yakmesh v1.5.1

**🦬 Yakmesh v1.5.1 Released**

## 🔧 Fixes & Improvements

### Identity Initialization Fix
Fixed oracle initialization order so node identity correctly derives from codebase hash as originally designed.

### Automatic Port Fallback
Nodes now automatically find the next available port if default ports (3000, 9001) are occupied - no more crashes on busy systems.

### Process Management Script
New `scripts/start.sh` for proper background process management:
```bash
./scripts/start.sh start   # Start in background
./scripts/start.sh stop    # Clean shutdown  
./scripts/start.sh restart # Stop + start
./scripts/start.sh status  # Check if running
./scripts/start.sh logs    # View logs
```

## 📦 Install/Upgrade
```bash
npm install yakmesh@1.5.1
```

---
🔗 https://yakmesh.dev | 💬 Discord: https://discord.gg/8mSPfbJB8N
