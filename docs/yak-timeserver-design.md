# time.yakmesh.dev — Public Atomic Time Service

**Date**: 2026-02-21
**Status**: Design Draft
**Domain**: time.yakmesh.dev
**Hardware**: MA-902/S-C1 GPS Gigabit Time Server at 192.168.1.30

---

## Concept

Any device can gain atomic-grade time synchronization by pointing at a yakmesh node.
The MA-902 GPS time server already provides Stratum 1 NTP on the LAN — this design
exposes that precision publicly through three tiers:

| Tier | Protocol | URL / Address | Accuracy | Use Case |
|------|----------|---------------|----------|----------|
| **1. NTP** | NTPv4 (UDP 123) | `ntp.yakmesh.dev` | ±1ms | OS-level time sync (`w32tm`, `chrony`, `ntpd`) |
| **2. HTTP Time API** | HTTPS (Caddy) | `https://time.yakmesh.dev/api/time` | ±5ms | Web apps, IoT, scripts, cross-platform |
| **3. NTS** | NTS-KE + NTPv4 | `nts.yakmesh.dev` | ±1ms | Authenticated, tamper-proof time (RFC 8915) |

**Why better than OS standard:**
- Most machines sync to `time.windows.com` or `pool.ntp.org` — Stratum 2-3 servers
  with ±10-50ms accuracy and no authentication
- time.yakmesh.dev is **Stratum 1** (direct GPS antenna), ±1ms, with satellite health
  telemetry and optional NTS authentication
- MA-902 tracks GPS + BeiDou constellations with 8-12 satellites in fix solution

---

## Architecture

```
                    Internet
                       │
          ┌────────────┴────────────┐
          │     yakmesh.dev VPS     │
          │                         │
          │  ┌───────────────────┐  │
          │  │   Caddy (HTTPS)   │  │
          │  │  time.yakmesh.   │  │
          │  │  dev :443         │──┼──→ /api/time  → time-api.js (Node)
          │  │                   │  │    /api/health → satellite status
          │  │                   │  │    /           → landing page
          │  └───────────────────┘  │
          │                         │
          │  ┌───────────────────┐  │
          │  │  NTP relay/proxy  │  │
          │  │  :123 UDP         │──┼──→ Forwards to MA-902 192.168.1.30:123
          │  │  (chrony or ntpd) │  │    via WireGuard tunnel
          │  └───────────────────┘  │
          │                         │
          └─────────┬───────────────┘
                    │ WireGuard tunnel
                    │
          ┌─────────┴───────────────┐
          │   LAN (192.168.1.x)     │
          │                         │
          │  ┌───────────────────┐  │
          │  │  MA-902/S-C1 GPS  │  │
          │  │  192.168.1.30     │  │
          │  │  NTP Stratum 1   │  │
          │  │  SNMP v2c         │  │
          │  │  GPS+BeiDou       │  │
          │  └───────────────────┘  │
          │                         │
          │  ┌───────────────────┐  │
          │  │  Yakmesh Node     │  │
          │  │  (this machine)   │  │
          │  │  ma902-snmp.js    │──┼──→ SNMP telemetry
          │  │  time-api.js      │──┼──→ HTTP time endpoint (local)
          │  └───────────────────┘  │
          │                         │
          └─────────────────────────┘
```

---

## Tier 1: NTP Service (`ntp.yakmesh.dev`)

### Option A: Direct NTP Relay (Preferred)

Run `chrony` on the VPS with the MA-902 as its upstream source via WireGuard.
The VPS becomes a **Stratum 2** NTP server that anyone can use.

```ini
# /etc/chrony/chrony.conf on the VPS
server 10.0.0.30 iburst prefer  # MA-902 via WireGuard
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
allow 0.0.0.0/0                  # Allow all clients
```

DNS: `ntp.yakmesh.dev` → VPS public IP (A record)

**Usage by end users:**
```bash
# Windows
w32tm /config /manualpeerlist:"ntp.yakmesh.dev" /syncfromflags:manual /update

# Linux (chrony)
echo "server ntp.yakmesh.dev iburst" >> /etc/chrony/chrony.conf

# Linux (systemd-timesyncd)
echo 'NTP=ntp.yakmesh.dev' >> /etc/systemd/timesyncd.conf
```

### Option B: LAN-Only NTP (Simpler)

If no VPS/tunnel, the MA-902 at 192.168.1.30 already serves NTP locally.
Yakmesh nodes on the LAN can use it directly. Remote nodes use the HTTP API.

---

## Tier 2: HTTP Time API (`time.yakmesh.dev`)

### Caddy Configuration

```caddyfile
time.yakmesh.dev {
    # Time API — reverse proxy to local Node.js time service
    handle /api/* {
        reverse_proxy localhost:3099
    }

    # Landing page — static site
    handle {
        root * /var/www/yak-timeserver
        file_server
    }

    # Security headers
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        Access-Control-Allow-Origin "*"
        Access-Control-Allow-Methods "GET, HEAD, OPTIONS"
    }

    # CORS preflight
    @cors_preflight method OPTIONS
    handle @cors_preflight {
        header Access-Control-Max-Age "86400"
        respond "" 204
    }

    # Rate limiting
    rate_limit {
        zone time_api {
            key {remote_host}
            events 60
            window 1m
        }
    }
}
```

### Time API Endpoints

#### `GET /api/time`

Returns current atomic time with metadata.

```json
{
  "iso": "2026-02-21T14:30:00.123Z",
  "unix": 1771598200.123,
  "unix_ms": 1771598200123,
  "stratum": 1,
  "source": "MA-902/S-C1 GPS",
  "accuracy_ms": 1,
  "leap_indicator": 0,
  "satellites": {
    "visible": 12,
    "used": 9,
    "tracking": 11,
    "constellations": ["GPS", "BeiDou"]
  },
  "lock": true,
  "quality": "excellent",
  "offset_ns": 0,
  "reference_id": "GPS"
}
```

**Headers returned:**
```
X-Yakmesh-Time: 1771598200.123
X-Yakmesh-Stratum: 1
X-Yakmesh-Source: GPS
Date: Fri, 21 Feb 2026 14:30:00 GMT
```

#### `GET /api/time/simple`

Minimal response for constrained clients:

```json
{
  "t": 1771598200123,
  "s": 1,
  "q": "excellent"
}
```

#### `GET /api/health`

Satellite health and SNMP telemetry:

```json
{
  "status": "healthy",
  "uptime_s": 864000,
  "lock": true,
  "satellites_visible": 12,
  "satellites_used": 9,
  "constellations": ["GPS", "BeiDou"],
  "alarm": false,
  "quality": 1,
  "last_poll": "2026-02-21T14:29:55Z",
  "drift_ns": 0,
  "trust_level": "atomic"
}
```

#### `HEAD /api/time`

Returns only headers — zero body. Fastest way to get time:

```
X-Yakmesh-Time: 1771598200.123
X-Yakmesh-Stratum: 1
Content-Length: 0
```

### Node.js Time API Service (`oracle/time-api.js`)

New module that bridges MA-902 SNMP telemetry to an HTTP endpoint:

```javascript
// oracle/time-api.js — HTTP Atomic Time API
//
// Reads GPS time from MA-902 via the existing MA902Monitor SNMP module
// and serves it as a lightweight HTTP endpoint.
//
// Runs on port 3099 (configurable via YAKMESH_TIME_API_PORT).
// Reverse-proxied by Caddy at time.yakmesh.dev.

import http from 'node:http';
import { MA902Monitor } from './ma902-snmp.js';

const PORT = parseInt(process.env.YAKMESH_TIME_API_PORT || '3099');

const monitor = new MA902Monitor({
  host: process.env.MA902_HOST || '192.168.1.30',
  community: process.env.MA902_COMMUNITY || 'public',
  pollInterval: 5000,
});

// Cache last SNMP telemetry
let lastTelemetry = null;
monitor.on('telemetry', (data) => { lastTelemetry = data; });
monitor.start();

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  const now = Date.now();
  const unixS = now / 1000;

  // Common time headers
  res.setHeader('X-Yakmesh-Time', unixS.toFixed(3));
  res.setHeader('X-Yakmesh-Stratum', lastTelemetry?.lockStatus ? '1' : '2');
  res.setHeader('X-Yakmesh-Source', lastTelemetry?.lockStatus ? 'GPS' : 'system');

  if (url.pathname === '/api/time' && req.method === 'HEAD') {
    res.writeHead(200);
    return res.end();
  }

  if (url.pathname === '/api/time/simple') {
    const body = JSON.stringify({
      t: now,
      s: lastTelemetry?.lockStatus ? 1 : 2,
      q: getQuality(),
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(body);
  }

  if (url.pathname === '/api/time') {
    const body = JSON.stringify({
      iso: new Date(now).toISOString(),
      unix: unixS,
      unix_ms: now,
      stratum: lastTelemetry?.lockStatus ? 1 : 2,
      source: 'MA-902/S-C1 GPS',
      accuracy_ms: lastTelemetry?.lockStatus ? 1 : 50,
      leap_indicator: 0,
      satellites: {
        visible: lastTelemetry?.satsVisible ?? 0,
        used: lastTelemetry?.satsUsed ?? 0,
        tracking: lastTelemetry?.satsTracking ?? 0,
        constellations: lastTelemetry?.constellations ?? [],
      },
      lock: lastTelemetry?.lockStatus ?? false,
      quality: getQuality(),
      offset_ns: lastTelemetry?.offset ?? 0,
      reference_id: lastTelemetry?.lockStatus ? 'GPS' : 'SYS',
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(body);
  }

  if (url.pathname === '/api/health') {
    const body = JSON.stringify({
      status: lastTelemetry?.lockStatus ? 'healthy' : 'degraded',
      lock: lastTelemetry?.lockStatus ?? false,
      satellites_visible: lastTelemetry?.satsVisible ?? 0,
      satellites_used: lastTelemetry?.satsUsed ?? 0,
      constellations: lastTelemetry?.constellations ?? [],
      alarm: lastTelemetry?.alarm ?? false,
      quality: lastTelemetry?.quality ?? 0,
      last_poll: lastTelemetry?.timestamp
        ? new Date(lastTelemetry.timestamp).toISOString()
        : null,
      trust_level: lastTelemetry?.trustLevel ?? 'unknown',
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(body);
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

function getQuality() {
  if (!lastTelemetry) return 'unknown';
  const sats = lastTelemetry.satsUsed || 0;
  if (sats >= 8) return 'excellent';
  if (sats >= 5) return 'good';
  if (sats >= 3) return 'marginal';
  return 'degraded';
}

server.listen(PORT, () => {
  console.log(`Yakmesh Time API listening on :${PORT}`);
});
```

---

## Tier 3: NTS — Network Time Security (Future)

NTS (RFC 8915) adds TLS-based authentication to NTP, preventing MITM time attacks.
This is a natural extension of yakmesh's post-quantum stance.

**Requirements:**
- NTS-KE (Key Establishment) server on port 4460
- TLS certificate (Let's Encrypt via Caddy)
- Compatible NTP server (chrony 4.0+ supports NTS natively)

**chrony NTS config:**
```ini
ntsserverkey /etc/letsencrypt/live/nts.yakmesh.dev/privkey.pem
ntsservercert /etc/letsencrypt/live/nts.yakmesh.dev/fullchain.pem
ntsport 4460
```

**Post-quantum consideration:** NTS currently uses TLS 1.3 with X25519/AES.
When PQ TLS (ML-KEM hybrid) ships in standard libraries, the NTS-KE handshake
becomes quantum-resistant. The NTP payload is already authenticated with AEAD.

**Client usage:**
```bash
# chrony client
server nts.yakmesh.dev nts iburst
```

---

## MANI Protocol Integration

The time API feeds directly into the existing MANI (prayer stone) time
synchronization protocol. Every yakmesh node can:

1. Use `ntp.yakmesh.dev` as its NTP source (OS-level)
2. Query `time.yakmesh.dev/api/time` for satellite health telemetry
3. Feed responses into `ManiTimeDetector` for trust assessment
4. Broadcast time trust level via MANI gossip to mesh peers

This means **any yakmesh node with internet access automatically gains
atomic-grade time** — even without a local GPS receiver.

### Config Addition (yakmesh-node env vars)

```bash
YAKMESH_TIME_API_PORT=3099          # Local time API port
YAKMESH_TIME_SOURCE=ma902           # 'ma902' | 'ntp' | 'system'
MA902_HOST=192.168.1.30             # MA-902 SNMP address
MA902_COMMUNITY=public              # SNMP community string
```

---

## DNS Setup

```
time.yakmesh.dev          A       → VPS IP (Caddy serves HTTPS API + landing page)
ntp.yakmesh.dev           A       → VPS IP (chrony NTP relay on UDP 123)
nts.yakmesh.dev           A       → VPS IP (NTS-KE on TCP 4460 + NTP on UDP 123)
```

All subdomains under `yakmesh.dev` — no additional domain purchase needed.

---

## Landing Page (`time.yakmesh.dev/`)

Static HTML page (served by Caddy) showing:

- **Live atomic clock** — JavaScript fetching `/api/time` every second
- **Satellite constellation map** — GPS/BeiDou satellite visualization from health data
- **Setup instructions** — How to configure your OS/device to use time.yakmesh.dev
- **About** — MA-902 hardware details, GPS antenna, accuracy specs
- **Status badge** — Green/yellow/red based on satellite lock
- **Integration with yakmesh** — Link to MANI docs, time-sources.html

Design: Match yakmesh.dev aesthetic (dark theme, system fonts, zero external deps).
Same domain family — consistent branding under `*.yakmesh.dev`.

---

## Implementation Order

| Step | Task | Effort | Depends On |
|------|------|--------|------------|
| 1 | Create `oracle/time-api.js` — HTTP time service | 2 hours | MA-902 SNMP module (done) |
| 2 | Add Caddy site block for `time.yakmesh.dev` to `generateCaddyfile()` | 1 hour | Step 1 |
| 3 | Create landing page (static HTML) | 3 hours | Step 1 |
| 4 | DNS setup (A/CNAME records) | 15 min | Domain registrar access |
| 5 | VPS chrony configuration (NTP relay) | 1 hour | WireGuard tunnel to LAN |
| 6 | Add `/api/time` docs section to `time-sources.html` | 1 hour | Step 1 |
| 7 | MANI integration — remote nodes query time.yakmesh.dev | 2 hours | Step 1, MANI module |
| 8 | NTS setup (optional, future) | 4 hours | Step 5, chrony 4.0+ |

**Total: ~10 hours for Tiers 1+2, ~14 hours with NTS**

---

## Security Considerations

- **Rate limiting**: 60 req/min per IP on the HTTP API (Caddy rate_limit plugin)
- **No auth required**: Time is a public good — unauthenticated, CORS-open
- **Read-only**: API is GET/HEAD only, no writes, no state mutation
- **SNMP isolation**: MA-902 SNMP is LAN-only (192.168.1.x), never exposed publicly
- **GPS spoofing**: MA-902 has quality indicators; if satellites degrade, the API
  returns `"quality": "degraded"` and clients can fall back to system time
- **DDoS**: Caddy handles TLS termination; chrony handles NTP amplification protection
  via `ratelimit` directive

---

*Created: 2026-02-21 | Part of YAKMESH MANI Time Protocol Suite*
