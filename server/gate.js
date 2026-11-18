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

// Cloudflare encodes the IPv4 anycast of a service in the low 32 bits of its
// AAAA answer under 2606:4700::/32 (2606:4700::6812:5f29 ≡ 104.18.95.41).
// A v6-only hostname is unreachable from a v4-only host — the embedded v4
// gives CONNECT a last-resort target when DNS offers no A records.
function cfEmbeddedV4(v6) {
  const m = /^2606:4700::([0-9a-f]{4}):([0-9a-f]{4})$/i.exec(v6);
  if (!m) return null;
  const h = m[1] + m[2];
  return [0, 2, 4, 6].map(i => parseInt(h.slice(i, i + 2), 16)).join('.');
}

// Same classification as publicAddr, but returns the full candidate list so
// CONNECT can fall through unroutable addresses in order (Happy-Eyeballs-lite):
// v6-only names decode their embedded CF v4 as trailing candidates.
// Results are cached ~60s per host: the gate resolves on every CONNECT while
// real clients hold a resolver cache — a per-connection lookup penalty on
// every subresource is a detectable proxy signature (and pure latency).
const DNS_CACHE_TTL = 60000;
const dnsCache = new Map(); // host -> { addrs, exp }  (classification at fill)
async function publicAddrs(host) {
  const h = String(host).replace(/^\[|\]$/g, '');
  const hit = dnsCache.get(h);
  if (hit && hit.exp > Date.now()) return hit.addrs;
  if (hit) dnsCache.delete(h);
  const addrs = await publicAddrsResolve(h);
  if (addrs.length) {
    if (dnsCache.size > 512) dnsCache.clear(); // bound: hosts are few
    dnsCache.set(h, { addrs, exp: Date.now() + DNS_CACHE_TTL });
  }
  return addrs;
}
async function publicAddrsResolve(h) {
  if (ALLOW_LAN) {
    try { return (await dns.lookup(h, { all: true })).map(a => a.address); }
    catch { return []; }
  }
  if (isPrivateHost(h)) return [];
  if (net.isIP(h)) return [h];
  try {
    const addrs = await dns.lookup(h, { all: true });
    if (!addrs.length || addrs.some(a => isPrivateHost(a.address))) return [];
    const list = addrs.map(a => a.address);
    if (list.every(a => a.includes(':'))) {
      const v4 = list.map(cfEmbeddedV4).filter(Boolean);
      return [...list, ...v4]; // real v6 first; embedded v4 as fallback
    }
    return list;
  } catch { return []; } // fail-closed: unresolvable is unfetchable anyway
}

// Hop-by-hop and identity-scrubbed headers — never forwarded upstream.
const DROP_REQ = new Set([
  'proxy-connection', 'proxy-authorization', 'connection', 'keep-alive',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
  // strip network identity — the gate speaks for the machine.
  // (user-agent/accept-language/dnt are NOT identity leaks: they are the
  // browser's uniform fingerprint — dropping them turns a crowd-identity
  // into a 1-of-1 beacon and trips challenge platforms that compare
  // HTTP headers against what the JS engine reports.)
  'x-forwarded-for', 'via',
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
      const httpSrv = http.createServer((req, res) => this._onRequest(req, res));
      httpSrv.on('connect', (req, sock, head) => this._onConnect(req, sock, head));
      httpSrv.on('clientError', (err, sock) => { try { sock.destroy(); } catch {} });
      // One port, two dialects: first byte 0x05 is a SOCKS5 greeting, anything
      // else is HTTP. SOCKS matters because clients (libsoup) refuse to
      // advertise h2 through an HTTP-proxy CONNECT but happily tunnel h2
      // through SOCKS — same raw tunnel, no crippled ALPN.
      const server = net.createServer(sock => {
        sock.once('data', first => {
          sock.unshift(first);
          if (first[0] === 0x05) this._onSocks(sock);
          else httpSrv.emit('connection', sock);
        });
        sock.on('error', () => sock.destroy());
      });
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

  // Walk the candidate list in order and hand the established upstream to
  // onReady; calls onFail if every candidate dies. Shared by the HTTP
  // CONNECT path and the SOCKS5 path — the tunnel itself is protocol-blind.
  _dialThru(clientSock, head, port, addrs, onReady, onFail) {
    let idx = 0;
    const tryNext = () => {
      if (idx >= addrs.length) { onFail(); return; }
      const upstream = net.connect(port, addrs[idx++], () => {
        upstream.removeListener('error', preErr);
        upstream.on('error', () => { upstream.destroy(); clientSock.destroy(); });
        onReady(upstream);
      });
      const preErr = () => { upstream.destroy(); tryNext(); };
      upstream.on('error', preErr);
      clientSock.on('error', () => upstream.destroy());
      upstream.setTimeout(120000, () => upstream.destroy());
    };
    tryNext();
  }

  async _onConnect(req, clientSock, head) {
    const m = /^([^:]+):(\d+)$/.exec(req.url || '');
    if (!m || !['443', '8443'].includes(m[2])) {
      clientSock.end('HTTP/1.1 405 Method Not Allowed\r\n\r\n');
      return;
    }
    // resolve now: refuses private targets and pins the tunnel to checked
    // addresses — no rebind window. TLS SNI still carries the hostname.
    // Candidates are tried in order: a dead first answer (v6 on a v4-only
    // host, unroutable anycast) must not kill the tunnel — browsers fall
    // through addresses, a proxy that doesn't is detectably broken.
    const addrs = await publicAddrs(m[1]).catch(() => []);
    if (!addrs.length) {
      clientSock.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return;
    }
    this._dialThru(clientSock, head, parseInt(m[2], 10), addrs,
      (upstream) => {
        clientSock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head?.length) upstream.write(head);
        upstream.pipe(clientSock); clientSock.pipe(upstream);
      },
      () => { try {
        clientSock.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); clientSock.destroy();
      } catch {} });
  }

  // ------------------------------------------------------------ SOCKS5 ----

  _socksReply(clientSock, rep) { // RFC 1928 reply codes
    try { clientSock.end(Buffer.from(
      [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); } catch {}
  }

  _onSocks(clientSock) {
    // greeting: VER NMETHODS METHODS — accumulate until complete (localhost
    // almost never splits, but a fragmented first segment is legal TCP)
    const gb = [];
    const onGreet = (chunk) => {
      gb.push(chunk);
      let gl = 0; for (const b of gb) gl += b.length;
      if (gl < 2) return;
      const g = Buffer.concat(gb);
      const need = 2 + g[1];                     // VER NMETHODS + methods
      if (gl < need) return;
      if (g[0] !== 0x05) { clientSock.removeListener('data', onGreet); clientSock.destroy(); return; }
      clientSock.removeListener('data', onGreet);
      clientSock.write(Buffer.from([0x05, 0x00])); // NO AUTH
      const rb = g.length > need ? [g.slice(need)] : [];
      this._socksReq(clientSock, rb);
    };
    clientSock.on('data', onGreet);
    clientSock.on('error', () => clientSock.destroy());
  }

  _socksReq(clientSock, rb) {
    const onReq = (chunk) => {
      if (chunk?.length) rb.push(chunk);
      let rl = 0; for (const b of rb) rl += b.length;
      if (rl < 5) return;
      const req = Buffer.concat(rb);
      if (req[0] !== 0x05 || req[1] !== 0x01 || req[2] !== 0x00)
        { clientSock.removeListener('data', onReq); this._socksReply(clientSock, 0x07); return; }
      const atyp = req[3];
      let total;
      if (atyp === 0x01) total = 10;                    // v4: 4+4+2
      else if (atyp === 0x03) total = 7 + req[4];       // dom: 4+1+len+2
      else if (atyp === 0x04) total = 22;               // v6: 4+16+2
      else { clientSock.removeListener('data', onReq); this._socksReply(clientSock, 0x08); return; }
      if (rl < total) return;
      clientSock.removeListener('data', onReq);
      const tail = rl > total ? req.slice(total) : null; // pipelined TLS head
      this._socksConnect(clientSock, req.slice(0, total), atyp, tail);
    };
    clientSock.on('data', onReq);
    onReq();                                            // buffered leftovers
  }

  async _socksConnect(clientSock, req, atyp, tail) {
    let host;
    if (atyp === 0x01) host = [...req.slice(4, 8)].join('.');
    else if (atyp === 0x03) host = req.slice(5, 5 + req[4]).toString('utf8');
    else host = req.slice(4, 20).toString('hex').match(/.{4}/g).join(':');
    const port = req.readUInt16BE(req.length - 2);
    if (![80, 443, 8080, 8443].includes(port))
      return this._socksReply(clientSock, 0x02); // not allowed by ruleset
    let addrs = await publicAddrs(host).catch(() => []);
    // v6 literal candidates: CF's embedded v4 rides along as a fallback
    if (atyp === 0x04 && addrs.every(a => a.includes(':'))) {
      const b = req.slice(4, 20);
      if (b[0] === 0x26 && b[1] === 0x06 && b[2] === 0x47 && b[3] === 0x00
          && b.slice(4, 12).every(x => x === 0))
        addrs = [...addrs, [...b.slice(12, 16)].join('.')];
    }
    if (!addrs.length) return this._socksReply(clientSock, 0x05);
    this._dialThru(clientSock, tail, port, addrs,
      (upstream) => {
        clientSock.write(
          Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]), () => {
          if (tail?.length) upstream.write(tail);
          upstream.pipe(clientSock); clientSock.pipe(upstream);
        });
      },
      () => this._socksReply(clientSock, 0x04)); // host unreachable
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
    // Forward the client's real browser identity (already kept in `headers`
    // above). Only non-browser callers get a baseline UA — and it must be a
    // mainstream string: a custom UA is a unique fingerprint, not privacy.
    if (!headers['user-agent'])
        headers['user-agent'] = 'Mozilla/5.0 (X11; Linux x86_64) '
            + 'AppleWebKit/605.1.15 (KHTML, like Gecko) '
            + 'Version/18.4 Safari/605.1.15';

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
