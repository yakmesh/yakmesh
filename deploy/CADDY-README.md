# Caddy Auto-SSL Integration for YAKMESH

This guide explains how to use Caddy as a reverse proxy for YAKMESH nodes,
providing automatic SSL/TLS certificates via Let's Encrypt or ZeroSSL.

## Why Caddy?

- **Automatic HTTPS** - Gets and renews certificates automatically
- **Zero Configuration** - Just specify your domain, Caddy handles the rest
- **HTTP/2 and HTTP/3** - Modern protocol support out of the box
- **Reverse Proxy** - Routes traffic to your yakmesh node
- **Production Ready** - Used by many production deployments

## Quick Start

### 1. Install Caddy

**Debian/Ubuntu:**
```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
```

**RHEL/CentOS/Fedora:**
```bash
dnf install 'dnf-command(copr)'
dnf copr enable @caddy/caddy
dnf install caddy
```

**macOS:**
```bash
brew install caddy
```

**Windows:**
```powershell
winget install Caddy.Caddy
# Or download from: https://caddyserver.com/download
```

### 2. Configure Your Domain

Edit the Caddyfile and replace `YOUR_DOMAIN.com` with your actual domain:

```bash
sudo nano /etc/caddy/Caddyfile
# Replace YOUR_DOMAIN.com with your-actual-domain.com
```

### 3. Point DNS to Your Server

Create an A record pointing your domain to your server's IP:

```
Type: A
Name: @ (or your subdomain)
Value: YOUR_SERVER_IP
TTL: 300
```

### 4. Start Caddy

```bash
# As a service (recommended)
sudo systemctl enable caddy
sudo systemctl start caddy

# Check status
sudo systemctl status caddy

# View logs
sudo journalctl -u caddy -f
```

### 5. Start Your YAKMESH Node

```bash
cd /path/to/yakmesh-node
npm start
```

Your node should now be accessible at `https://your-domain.com`!

## Architecture

```
Internet
    │
    ▼
┌──────────────────────────────────────┐
│  Caddy (Port 443, HTTPS)             │
│  - Auto SSL via Let's Encrypt        │
│  - HTTP/2, HTTP/3 support            │
│  - Security headers                  │
└──────────────────────────────────────┘
    │
    ├─── /.well-known/yakmesh/* ───▶ localhost:9000 (SHERPA Beacon)
    │
    ├─── /ws ──────────────────────▶ localhost:9001 (WebSocket)
    │
    ├─── /annex/* ─────────────────▶ localhost:9000 (ANNEX Content)
    │
    └─── /api/* ───────────────────▶ localhost:9000 (REST API)
```

## Certificate Information for NAMCHE

When Caddy obtains a certificate, you can extract its fingerprint for use
in the SHERPA beacon's `namche.ssl` fields:

```bash
# Get certificate fingerprint
openssl s_client -connect your-domain.com:443 -servername your-domain.com 2>/dev/null \
  | openssl x509 -fingerprint -sha256 -noout \
  | cut -d= -f2
```

The yakmesh node can automatically populate the beacon's SSL fields:

```javascript
// In your node configuration
beacon.namche.ssl = {
  hasPublicCert: true,
  certFingerprint: 'sha256:AB:CD:EF:...',
  issuer: 'letsencrypt',
  domains: ['your-domain.com'],
  expiresAt: certificateExpiryTimestamp,
};
```

## Development Mode

For local development without a real domain, use the `:8443` block
which uses a self-signed certificate:

```bash
caddy run --config deploy/Caddyfile
```

Then access: `https://localhost:8443`

## Troubleshooting

### Certificate Issues

```bash
# Check certificate status
caddy trust  # Trust Caddy's CA for local dev
caddy validate --config /etc/caddy/Caddyfile

# Force certificate renewal
caddy reload --config /etc/caddy/Caddyfile
```

### Port Conflicts

Make sure ports 80 and 443 are available:
```bash
sudo lsof -i :80
sudo lsof -i :443
```

### Firewall

```bash
# Allow HTTP/HTTPS
sudo ufw allow 80
sudo ufw allow 443
```

### DNS Propagation

Verify DNS is pointing correctly:
```bash
dig your-domain.com +short
nslookup your-domain.com
```

## Integration with NAMCHE

The Caddy SSL certificate provides a "bridge" between traditional PKI
(browser-trusted certificates) and YAKMESH's trustless verification:

1. **Traditional clients** (browsers) trust the Let's Encrypt certificate
2. **YAKMESH nodes** verify the beacon signature using ML-DSA-65
3. **Domain claims** are verified through multi-node consensus

This hybrid approach allows:
- Public web access with familiar HTTPS trust
- Mesh communication with post-quantum security
- Domain ownership proofs for the DOKO certificate

## See Also

- [NAMCHE Specification](../docs/NAMCHE-SPEC.md)
- [SHERPA Discovery](../mesh/sherpa-discovery.js)
- [Caddy Documentation](https://caddyserver.com/docs/)
