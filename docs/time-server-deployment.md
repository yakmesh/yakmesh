# time.yakmesh.dev — Self-Hosted Deployment Guide

**Date**: 2026-02-22
**Architecture**: Home-hosted — DNS points to home IP, AX3000 port-forwards to LAN
**Domain**: `time.yakmesh.dev` (single domain for NTP + HTTPS + API)

---

## Architecture Overview

```
Internet
  │
  ├─ UDP 123  ──→  AX3000  ──→  MA-902 (192.168.1.30)     NTP responses
  │                              Stratum 1 GPS hardware
  │
  └─ TCP 443  ──→  AX3000  ──→  Yakmesh Node (LAN server)  HTTPS
                                  ├─ Caddy (TLS termination)
                                  ├─ website/time/index.html  (landing page)
                                  └─ time-api.js :3099        (GPS telemetry API)
                                      └─ SNMP → MA-902 (192.168.1.30)
```

**Key insight**: The yakmesh node and MA-902 are on the same LAN. The node can poll
the MA-902 via SNMP and serve live satellite telemetry over HTTPS. Same domain,
same DNS record, two protocols (UDP for NTP, TCP for HTTPS) — no conflict.

---

## 1. DNS — Point time.yakmesh.dev to Home IP

In **Hostinger hPanel → DNS Zone Editor** for `yakmesh.dev`:

| Type | Name   | Value            | TTL  |
|------|--------|------------------|------|
| A    | time   | `<your-home-IP>` | 3600 |

Find your home IP: `curl ifconfig.me` from the LAN server.

> **CGNAT check**: Your router's WAN IP must match `ifconfig.me`.
> If they differ, you're behind carrier-grade NAT and need Workaround 2
> (tunnel via external VPS). See `ntp server.md` for details.

> **Dynamic IP**: If your ISP changes your IP, set up a cron job or script
> to update the A record via Hostinger's API. Or use a DDNS service.

---

## 2. AX3000 Port Forwarding

In the TP-Link AX3000 admin panel (typically `192.168.1.1`):

**Advanced → NAT Forwarding → Port Forwarding** (or Virtual Servers):

| Service   | Protocol | External Port | Internal IP    | Internal Port |
|-----------|----------|---------------|----------------|---------------|
| NTP       | UDP      | 123           | 192.168.1.30   | 123           |
| HTTPS     | TCP      | 443           | `<node-IP>`    | 443           |

- **NTP** goes directly to the MA-902 — it speaks NTPv4 natively
- **HTTPS** goes to the yakmesh node running Caddy (which terminates TLS and
  proxies `/api/*` to `time-api.js` on port 3099, serves static HTML for everything else)

Optional — also forward **TCP 80** (HTTP) to the node so Caddy can handle ACME
challenges for Let's Encrypt certificate provisioning and HTTP→HTTPS redirects.

---

## 3. Start time-api.js on the Node

The time API bridges MA-902 SNMP telemetry to HTTP/JSON endpoints.

```bash
# From the yakmesh-node directory
node oracle/time-api.js
```

Or integrate into the main node startup (server/index.js):

```js
import { startTimeApi } from '../oracle/time-api.js';
await startTimeApi();  // Starts on port 3099
```

**Endpoints served:**
- `GET /api/time` — Full time + satellite telemetry
- `GET /api/time/simple` — Minimal `{ t, s, q }`
- `GET /api/health` — MA-902 health + alarm status
- `HEAD /api/time` — Headers only, `X-Yakmesh-Time`

---

## 4. Start Caddy

```bash
cd yakmesh-node
caddy run --config deploy/Caddyfile
```

Caddy will:
- Auto-provision Let's Encrypt TLS cert for `time.yakmesh.dev`
- Serve `website/time/index.html` for browser requests
- Reverse proxy `/api/*` to `localhost:3099` (time-api.js)
- Handle CORS, compression, security headers

> **Override static root**: Set `YAKMESH_TIME_ROOT` env var if the website files
> are in a different location than `./website/time`.

---

## 5. Verify

```bash
# NTP — should get a time response from the MA-902
ntpdate -q time.yakmesh.dev
# or
w32tm /stripchart /computer:time.yakmesh.dev /samples:3

# HTTPS landing page
curl -I https://time.yakmesh.dev/

# Time API
curl https://time.yakmesh.dev/api/time | jq .

# Health
curl https://time.yakmesh.dev/api/health | jq .
```

---

## 6. Hostinger — Banner on Main Site

The main `yakmesh.dev` site on Hostinger gets a small banner/badge promoting
the time server. No time-specific pages need to be hosted on Hostinger.

Hostinger subdomains `ntp.yakmesh.dev` and `nts.yakmesh.dev` can either:
- Point DNS to home IP (same as `time.yakmesh.dev`)
- Stay on Hostinger serving simple redirect pages (`website/ntp/`, `website/nts/`)

---

## Firewall Checklist

| Port     | Protocol | Direction | Purpose                         |
|----------|----------|-----------|----------------------------------|
| 123      | UDP      | Inbound   | NTP → MA-902                    |
| 443      | TCP      | Inbound   | HTTPS → Caddy → landing + API  |
| 80       | TCP      | Inbound   | HTTP → Caddy (ACME + redirect) |
| 161      | UDP      | LAN only  | SNMP v2c → MA-902 (never WAN)  |

**Never expose SNMP (UDP 161) to the internet.** The MA-902 SNMP interface
is LAN-only; `time-api.js` bridges it to sanitized JSON over HTTPS.

---

## Future Enhancements

- **NTS (Network Time Security)**: When chrony 4.0+ is integrated, enable NTS-KE
  on port 4460 for tamper-proof authenticated NTP (RFC 8915)
- **WireGuard tunnel**: If migrating to a VPS, tunnel NTP traffic from VPS → home
  via WireGuard, keeping the MA-902 as the Stratum 1 source
- **DDNS automation**: Script to update Hostinger A record on IP change

---

*Created: 2026-02-22 | Architecture: Self-hosted (Home-Base method)*
