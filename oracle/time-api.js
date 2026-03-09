/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * ╔═══════════════════════════════════════════════════════════════════════════════╗
 * ║                 ⏱️  YAKMESH TIME API — ATOMIC CLOCK SERVICE  ⏱️             ║
 * ╠═══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  HTTP endpoint that serves GPS-derived atomic time from the MA-902/S-C1      ║
 * ║  GPS Gigabit Time Server via the existing SNMP monitor module.               ║
 * ║                                                                               ║
 * ║  Runs on port 3099 (configurable via YAKMESH_TIME_API_PORT).                 ║
 * ║  Reverse-proxied by Caddy at time.yakmesh.dev.                               ║
 * ║                                                                               ║
 * ║  Endpoints:                                                                   ║
 * ║    GET  /api/time         — Full time + satellite telemetry (JSON)            ║
 * ║    GET  /api/time/simple  — Minimal { t, s, q } response                     ║
 * ║    GET  /api/health       — Satellite health + alarm status                   ║
 * ║    HEAD /api/time         — Headers only, zero body                           ║
 * ║                                                                               ║
 * ╚═══════════════════════════════════════════════════════════════════════════════╝
 *
 * @module oracle/time-api
 */

import http from 'node:http';
import { getMA902Monitor } from './ma902-snmp.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('time-api');

const PORT = parseInt(process.env.YAKMESH_TIME_API_PORT || '3099', 10);
const HOST = process.env.YAKMESH_TIME_API_HOST || '0.0.0.0';

// ============================================================
// MA-902 MONITOR — cached telemetry from SNMP polling
// ============================================================

let lastTelemetry = null;
let monitor = null;

/**
 * Initialize the MA-902 monitor and begin SNMP polling.
 * Telemetry updates are cached in `lastTelemetry` for low-latency HTTP responses.
 */
function initMonitor() {
  monitor = getMA902Monitor({
    host: process.env.MA902_HOST || '192.168.1.30',
    community: process.env.MA902_COMMUNITY || 'public',
    pollInterval: parseInt(process.env.MA902_POLL_INTERVAL || '5000', 10),
    verbose: process.env.MA902_VERBOSE === 'true',
  });

  monitor.on('telemetry', (data) => {
    lastTelemetry = data;
  });

  monitor.on('error', (err) => {
    log.warn('MA-902 monitor error', { error: err.message });
  });

  return monitor;
}

// ============================================================
// QUALITY ASSESSMENT
// ============================================================

/**
 * Derive a human-readable quality string from telemetry.
 * Matches the thresholds in ma902-snmp.js: excellent(≥8), good(≥5), marginal(≥3), degraded(≥1).
 */
function getQuality() {
  if (!lastTelemetry) return 'unknown';
  if (!lastTelemetry.locked) return 'degraded';
  const sats = lastTelemetry.satellites?.used || 0;
  if (sats >= 8) return 'excellent';
  if (sats >= 5) return 'good';
  if (sats >= 3) return 'marginal';
  return 'degraded';
}

// ============================================================
// HTTP SERVER
// ============================================================

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  const pathname = url.pathname;

  // CORS — time is a public good
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Max-Age', '86400');
    res.writeHead(204);
    return res.end();
  }

  // Timing headers on every response
  const now = Date.now();
  const unixS = now / 1000;
  const locked = lastTelemetry?.locked ?? false;

  res.setHeader('X-Yakmesh-Time', unixS.toFixed(3));
  res.setHeader('X-Yakmesh-Stratum', locked ? '1' : '2');
  res.setHeader('X-Yakmesh-Source', locked ? 'GPS' : 'system');

  // ---- HEAD /api/time — zero body ----
  if (pathname === '/api/time' && req.method === 'HEAD') {
    res.writeHead(200);
    return res.end();
  }

  // ---- GET /api/time/simple — minimal response ----
  if (pathname === '/api/time/simple' && req.method === 'GET') {
    const body = JSON.stringify({
      t: now,
      s: locked ? 1 : 2,
      q: getQuality(),
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(body);
  }

  // ---- GET /api/time — full atomic time with telemetry ----
  if (pathname === '/api/time' && req.method === 'GET') {
    const sats = lastTelemetry?.satellites || {};
    const body = JSON.stringify({
      iso: new Date(now).toISOString(),
      unix: unixS,
      unix_ms: now,
      stratum: locked ? 1 : 2,
      source: 'MA-902/S-C1 GPS',
      accuracy_ms: locked ? 1 : 50,
      leap_indicator: 0,
      satellites: {
        visible: sats.visible ?? 0,
        used: sats.used ?? 0,
        tracking: sats.tracking ?? 0,
        constellations: sats.constellations ?? [],
      },
      lock: locked,
      quality: getQuality(),
      offset_ns: lastTelemetry?.offset ?? 0,
      reference_id: locked ? 'GPS' : 'SYS',
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(body);
  }

  // ---- GET /api/health — satellite health & SNMP telemetry ----
  if (pathname === '/api/health' && req.method === 'GET') {
    const body = JSON.stringify({
      status: locked ? 'healthy' : 'degraded',
      lock: locked,
      satellites_visible: lastTelemetry?.satellites?.visible ?? 0,
      satellites_used: lastTelemetry?.satellites?.used ?? 0,
      constellations: lastTelemetry?.satellites?.constellations ?? [],
      alarm: lastTelemetry?.alarm ?? false,
      quality: lastTelemetry?.satellites?.quality ?? 'unknown',
      last_poll: lastTelemetry?.timestamp
        ? new Date(lastTelemetry.timestamp).toISOString()
        : null,
      drift_ns: lastTelemetry?.offset ?? 0,
      trust_level: lastTelemetry?.maniTrust?.level ?? 'unknown',
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(body);
  }

  // ---- GET / — redirect to info page on yakmesh.dev ----
  if (pathname === '/' && req.method === 'GET') {
    res.writeHead(302, { 'Location': 'https://yakmesh.dev/time/' });
    return res.end();
  }

  // ---- 404 ----
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found', endpoints: ['/api/time', '/api/time/simple', '/api/health'] }));
});

// ============================================================
// STARTUP
// ============================================================

/**
 * Start the Time API server and MA-902 monitor.
 * @returns {{ server: http.Server, monitor: MA902Monitor }}
 */
export async function startTimeApi() {
  const mon = initMonitor();
  const started = await mon.start();

  if (!started) {
    log.warn('MA-902 SNMP not available — Time API will return system time (Stratum 2)');
  }

  return new Promise((resolve, reject) => {
    server.listen(PORT, HOST, () => {
      log.info('Yakmesh Time API listening', { url: `http://${HOST}:${PORT}`, monitor: started ? 'MA-902 SNMP active' : 'system fallback' });
      resolve({ server, monitor: mon });
    });
    server.on('error', (err) => {
      log.error('Time API failed to start', { error: err.message });
      reject(err);
    });
  });
}

/**
 * Stop the Time API server and monitor.
 */
export async function stopTimeApi() {
  if (monitor) {
    monitor.stop();
    monitor = null;
    lastTelemetry = null;
  }
  return new Promise((resolve) => {
    server.close(() => {
      log.info('Yakmesh Time API stopped');
      resolve();
    });
  });
}

// ---- Direct execution support ----
// node oracle/time-api.js
const isMain = import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}`;
if (isMain) {
  startTimeApi().catch((err) => {
    console.error('Fatal:', err.message);
    process.exit(1);
  });
}

export default { startTimeApi, stopTimeApi };
