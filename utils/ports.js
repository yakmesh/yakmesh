/**
 * YakOS port registry — tools/ports/ports.mjs (canonical copy)
 *
 * Policy (2026-09-28): no more hardcoded ports. A service that binds a
 * port resolves candidates in this order:
 *   1. explicit env/config override (operator intent wins)
 *   2. the registry value (~/.config/yakos/ports.json)
 *   3. the preferred default
 *   4. preferred+N fallback probes
 * Whatever actually binds is persisted back to the registry so every
 * consumer discovers the real port from the same file. Where no
 * registry exists (e.g. shared hosting), reads return {} and writes
 * fail-soft — behaviour is identical to today.
 */

import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'fs';
import { connect } from 'net';
import { dirname, join } from 'path';
import { homedir } from 'os';

const REG_PATH =
  process.env.YAKOS_PORTS_FILE || join(homedir(), '.config', 'yakos', 'ports.json');

const CLAIMS_DIR = join(dirname(REG_PATH), 'ports.d');
const claimPath = (name) => join(CLAIMS_DIR, `${name}.json`);

/** Every service's self-claim — live truth even before aggregation. */
export function readClaims() {
  const out = {};
  let ents = [];
  try { ents = readdirSync(CLAIMS_DIR); } catch { return out; }
  for (const e of ents) {
    if (!e.endsWith('.json')) continue;
    try {
      const c = JSON.parse(readFileSync(join(CLAIMS_DIR, e), 'utf8'));
      if (c && c.name && c.port > 0) out[c.name] = c;
    } catch { /* partial claim — skip */ }
  }
  return out;
}

/** Read the registry map { name: port }. Missing/corrupt → {}. */
export function readPorts() {
  try {
    return JSON.parse(readFileSync(REG_PATH, 'utf8')).ports || {};
  } catch {
    return {};
  }
}

/** The port a service is bound on: live claim first, registry second. */
export function servicePort(name, fallback = null) {
  return readClaims()[name]?.port ?? readPorts()[name] ?? fallback;
}

/**
 * Ordered candidate ports for a bind loop.
 * envPort (explicit operator override) always wins, then the remembered
 * port, then preferred, then preferred+1..+probes-1.
 */
export function portCandidates(name, preferred, { probes = 10, envPort = null } = {}) {
  const out = [];
  const push = (p) => { if (Number.isInteger(p) && p > 0 && !out.includes(p)) out.push(p); };
  // Explicit operator override bypasses the registry entirely — binding a
  // remembered port when env says otherwise would be its own silent fail.
  if (envPort) {
    push(envPort);
    for (let i = 1; i < probes; i++) push(envPort + i);
    return out;
  }
  // Preferred home first, remembered port second: a service that drifted
  // off its home port because of a transient squatter should reclaim home
  // on the next start rather than cement the drift (2026-09-28).
  push(preferred);
  push(servicePort(name));
  for (let i = 1; i < probes; i++) push(preferred + i);
  return out;
}

/**
 * Chronological ordering contract: consumers may start before providers.
 * Resolve the service's port, then poll a TCP connect until it answers or
 * `timeoutMs` expires. Returns { port, ready } — callers log, never hang.
 */
export async function waitServicePort(name, fallback, { timeoutMs = 30000, intervalMs = 250, host = '127.0.0.1' } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const port = servicePort(name, fallback);
    const ready = await new Promise((resolve) => {
      const s = connect({ host, port }, () => { s.end(); resolve(true); });
      s.on('error', () => resolve(false));
      s.setTimeout(500, () => { s.destroy(); resolve(false); });
    });
    if (ready) return { port, ready: true };
    if (Date.now() > deadline) return { port, ready: false };
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

/**
 * Persist the port a service actually bound. Returns true on success —
 * callers should log failures, never swallow them.
 */
export function rememberPort(name, port) {
  // A service writes ONLY its own claim file — ports.d/<name>.json —
  // never the shared registry. yakos-verifyd is the sole writer of the
  // merged ports.json (single-writer orchestration, 2026-09-28).
  try {
    mkdirSync(CLAIMS_DIR, { recursive: true });
    const claim = {
      name, port,
      pid: process.pid,
      exe: process.argv[1] ? process.argv[1].split('/').pop() : 'node',
      ts: Math.floor(Date.now() / 1000),
    };
    const tmp = `${claimPath(name)}.tmp`;
    writeFileSync(tmp, JSON.stringify(claim, null, 2) + '\n');
    renameSync(tmp, claimPath(name));
    return true;
  } catch {
    return false;
  }
}
