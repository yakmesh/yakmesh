/**
 * YAKGATE — the node's local web gateway.
 *
 * yakbrowse (and any local app) points its HTTP proxy here. All web traffic
 * then flows through the running node — the mesh is the browser's security
 * net, not the other way around.
 *
 * Binds 127.0.0.1 only: :3080 serves the mesh on wildcard, but the gate is a
 * forward proxy — remote reachability would make it an open relay. Loopback
 * binding makes that structurally impossible, no ACL to get wrong.
 *
 * Two modes:
 *   GET http://host/path  (absolute-URI proxy form) — fetch upstream,
 *        stream back. Plain-HTTP requests carry no identity by default.
 *   CONNECT host:443      — raw TLS tunnel. End-to-end encryption preserved;
 *        gate sees destination host only. (HTTPS content inspection is the
 *        optional MITM milestone — local CA, opt-in, see CONFIDENTIAL spec.)
 *
 * YakMesh PID auth — the PID is never on the wire. Challenge → ping:
 *   If an upstream responds `YakMesh-Challenge: <nonce>`, the gate registers
 *   the nonce (60s window) and retries once carrying only a node pointer:
 *     X-YakAuth-Node: <this node's HTTP endpoint>
 *   The site then pings the NODE out-of-band: POST /api/yakauth/attest
 *   {nonce, host, session} → node signs pid||host||nonce||session||ts
 *   (ML-DSA-65, hardware keystore via :9995) and returns
 *   {pid, nodeId, ts, signature, keyId}. Site verifies sig, binds its
 *   session to the pid. The browser channel carries no identity — the pid
 *   travels node->site only, and only for nonces the node observed passing
 *   through its own gate (so remote parties cannot ping the node to
 *   harvest the pid).
 */

import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns/promises';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { portCandidates, rememberPort } from '../utils/ports.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PQ_SIGN = 'http://127.0.0.1:9995/sign';
const ALLOW_LAN = process.env.YAKGATE_LAN === '1'; // escape hatch, off by default
const FETCH_PORTS = new Set(['', '80', '443', '8080', '8443']);
const MAX_CHALLENGES = 256;

// SSRF guard: the gate must not become a LAN-read primitive for web content
// (it bypasses the browser's own Private Network Access checks). Any private/
// loopback/reserved literal or resolution result is refused.
function isPrivateHost(host) {
  const h = String(host).replace(/^\[|\]$/g, '').toLowerCase();
  if (!h || h === 'localhost' || h.endsWith('.localhost')
      || h.endsWith('.local') || h.endsWith('.internal')) return true;
  const v4m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(h);
  if (v4m) return isPrivateHost(v4m[1]);
  if (h === '::1' || h === '::') return true;
  if (h.includes(':') && /^(fc|fd|fe80)/.test(h)) return true; // ULA + link-local
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return false; // hostname — resolved separately
  const a = +m[1], b = +m[2];
  return a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 169 && b === 254) || (a === 192 && b === 168)
      || (a === 172 && b >= 16 && b <= 31) || (a === 100 && b >= 64 && b <= 127);
}

// Resolve + classify. Returns a public IP for CONNECT (pins against DNS
// rebinding — the tunnel only carries TLS to the resolved address), or null
// to refuse. Fetch mode uses the boolean only (libuv re-resolves at connect;
// residual TOCTOU window accepted, documented in the spec).
async function publicAddr(host) {
  const h = String(host).replace(/^\[|\]$/g, '');
  if (ALLOW_LAN) {
    try { return (await dns.lookup(h)).address; } catch { return null; }
  }
  if (isPrivateHost(h)) return null;
  if (net.isIP(h)) return h; // public literal
  try {
    const addrs = await dns.lookup(h, { all: true });
    if (!addrs.length || addrs.some(a => isPrivateHost(a.address))) return null;
    return addrs[0].address;
  } catch { return null; } // fail-closed: unresolvable is unfetchable anyway
}

// Hop-by-hop and identity-scrubbed headers — never forwarded upstream.
const DROP_REQ = new Set([
  'proxy-connection', 'proxy-authorization', 'connection', 'keep-alive',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
  // strip ambient client identity — the gate speaks for the machine
  'user-agent', 'accept-language', 'dnt', 'x-forwarded-for', 'via',
]);
const DROP_RES = new Set([
  'connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'te', 'trailer',
  'proxy-authenticate', 'proxy-authorization',
]);

export class YakGate {
  constructor({ port = 3089, authEndpoint = null } = {}) {
    this.port = port;
    this.authEndpoint = authEndpoint; // advertised in X-YakAuth-Node
    this.server = null;
    this._pid = null;
    this._pidTried = false;
    this._challenges = new Map(); // nonce -> { host, at }  (60s attest window)
  }

  /** True + consume if this nonce passed through the gate recently. */
  consumeChallenge(nonce, host) {
    const c = this._challenges.get(nonce);
    if (!c || c.host !== host || Date.now() - c.at > 60000) return false;
    this._challenges.delete(nonce);
    return true;
  }

  _sweep() { // keep the nonce table bounded
    const now = Date.now();
    for (const [n, c] of this._challenges)
      if (now - c.at > 60000) this._challenges.delete(n);
  }

  /** Canonical persistentId from the machine seed (personhood anchor). */
  persistentId() {
    if (this._pid || this._pidTried) return this._pid;
    this._pidTried = true;
    try {
      const seed = JSON.parse(readFileSync(join(ROOT, 'data/machine-seed.json'), 'utf8'));
      this._pid = seed.persistentId || null;
    } catch { this._pid = null; }
    return this._pid;
  }

  /** ML-DSA-65 sign via the YakOS PQ bridge (hardware keystore). */
  async pqSign(message) {
    const body = JSON.stringify({ message_b64: Buffer.from(message).toString('base64') });
    const r = await fetch(PQ_SIGN, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) throw new Error('pq-sign ' + r.status);
    return r.json(); // { signature, key_id, algorithm }
  }

  start() {
    // Registry-aware candidates — remembered gate port first, explicit
    // YAKMESH_GATE_PORT bypasses the registry (operator intent wins).
    const candidates = portCandidates('yakmesh-gate', this.port, {
      probes: 4,
      envPort: process.env.YAKMESH_GATE_PORT ? parseInt(process.env.YAKMESH_GATE_PORT, 10) : null,
    });
    const tryPort = (i) => new Promise((resolve, reject) => {
      const port = candidates[i];
      const server = http.createServer((req, res) => this._onRequest(req, res));
      server.on('connect', (req, sock, head) => this._onConnect(req, sock, head));
      server.on('clientError', (err, sock) => { try { sock.destroy(); } catch {} });
      server.once('error', (err) => {
        if (err.code === 'EADDRINUSE' && i + 1 < candidates.length)
          return tryPort(i + 1).then(resolve, reject);
        reject(err);
      });
      server.listen(port, '127.0.0.1', () => { this.port = port; this.server = server; resolve(); }); // loopback ONLY — never wildcard
    });
    return tryPort(0).then(() => {
      if (!rememberPort('yakmesh-gate', this.port))
        console.warn('[yakgate] could not record port in ~/.config/yakos/ports.json');
    });
  }

  stop() { try { this.server?.close(); } catch {} }

  // ----------------------------------------------------------- CONNECT ----

  async _onConnect(req, clientSock, head) {
    const m = /^([^:]+):(\d+)$/.exec(req.url || '');
    if (!m || !['443', '8443'].includes(m[2])) {
      clientSock.end('HTTP/1.1 405 Method Not Allowed\r\n\r\n');
      return;
    }
    // resolve now: refuses private targets and pins the tunnel to the checked
    // address — no rebind window. TLS SNI still carries the hostname.
    const addr = await publicAddr(m[1]).catch(() => null);
    if (!addr) {
      clientSock.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return;
    }
    const upstream = net.connect(parseInt(m[2], 10), addr, () => {
      clientSock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head?.length) upstream.write(head);
      upstream.pipe(clientSock); clientSock.pipe(upstream);
    });
    const fail = () => { try {
      clientSock.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); clientSock.destroy();
      upstream.destroy();
    } catch {} };
    upstream.on('error', fail); clientSock.on('error', fail);
    upstream.setTimeout(120000, () => upstream.destroy());
  }

  // ---------------------------------------------------------- fetch mode --

  async _onRequest(req, res) {
    let url;
    try { url = new URL(req.url); } catch {
      res.writeHead(400); res.end('yakgate: proxy-form (absolute URI) only'); return;
    }
    if (!/^https?:$/.test(url.protocol)) {
      res.writeHead(403); res.end('yakgate: http/https only'); return;
    }
    if (!FETCH_PORTS.has(url.port)) {
      res.writeHead(403); res.end('yakgate: web ports only'); return;
    }
    if (!(await publicAddr(url.hostname).catch(() => null))) {
      res.writeHead(403); res.end('yakgate: private/unresolvable target refused'); return;
    }
    const headers = {};
    for (const [k, v] of Object.entries(req.headers))
      if (!DROP_REQ.has(k.toLowerCase())) headers[k] = v;
    headers['host'] = url.host; // canonicalize — never trust the client Host
    headers['user-agent'] = 'YakBrowse/1.0 (yakgate)';

    await this._fetch(url, req.method, headers, req, res, false);
  }

  async _fetch(url, method, headers, clientReq, clientRes, isAuthRetry) {
    const mod = url.protocol === 'https:' ? await import('node:https') : http;
    const up = mod.request(url, { method, headers, timeout: 30000 }, async (upRes) => {
      // pid-ping model: register the nonce, retry carrying ONLY the node
      // pointer — the site attests out-of-band at /api/yakauth/attest
      const nonce = upRes.headers['yakmesh-challenge'];
      if (nonce && !isAuthRetry && this.persistentId() && this.authEndpoint) {
        const host = url.host;
        this._sweep();
        if (this._challenges.size < MAX_CHALLENGES)
          this._challenges.set(String(nonce), { host, at: Date.now() });
        upRes.resume(); // drain before retry
        return this._fetch(url, method,
          { ...headers, 'x-yakauth-node': this.authEndpoint },
          clientReq, clientRes, true);
      }
      const rh = { 'x-yakgate': 'yakmesh-node' };
      for (const [k, v] of Object.entries(upRes.headers))
        if (!DROP_RES.has(k.toLowerCase())) rh[k] = v;
      clientRes.writeHead(upRes.statusCode, rh);
      upRes.pipe(clientRes);
    });
    up.on('timeout', () => up.destroy(new Error('upstream timeout')));
    up.on('error', (e) => {
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'content-type': 'text/plain' });
        clientRes.end('yakgate: ' + e.message + ' — ' + url.host +
          '\n(node is your gateway; check the target or mesh state)');
      } else clientRes.destroy();
    });
    // note: on the auth retry path clientReq is already consumed — GET/HEAD
    // (what a challenge answers, a page load) carry no body, so the resend
    // is exact. Bodied retries stream empty; acceptable until the gate
    // buffers bodies for retry.
    clientReq.pipe(up);
  }
}

export default YakGate;
