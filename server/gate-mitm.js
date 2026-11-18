/**
 * GATE-MITM — TLS boundary termination (opt-in).
 *
 * The raw CONNECT/SOCKS tunnel carries the client's TLS byte-for-byte, which
 * means the client's TLS library fingerprint (JA4) and HTTP protocol reach
 * the edge verbatim. libsoup-through-CONNECT proved fatal: it forced
 * http/1.1, and challenge platforms score that profile bot-tier no matter
 * how human the operator is.
 *
 * MITM cuts the connection at the gate:
 *   browser --TLS--> gate (minted cert, local per-install CA)
 *   gate    --TLS h2--> origin (our client, our fingerprint)
 *
 * What the edge sees is OUR request — a uniform Node h2 fingerprint shared
 * by every meshed gate. Crowd identity instead of per-client identity: the
 * mesh literally becomes the browser's protocol voice.
 *
 * Trust: a per-install CA in data/gate-mitm/ (gitignored — the key never
 * leaves the machine). Clients trust the public cert; openssl does the
 * minting (no npm dep).
 *
 * Safety:
 *   - OFF unless YAKGATE_MITM is set: 'all' or a comma list of suffixes.
 *   - A client that refuses our handshake falls back to the raw tunnel —
 *     the pre-handshake bytes are replayed upstream, so untrusted clients
 *     degrade to today's behavior instead of breaking.
 *   - Still loopback-only by construction (the listener enforces it).
 *   - Plaintext exists only in-process; nothing is logged.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import tls from 'node:tls';
import http from 'node:http';
import http2 from 'node:http2';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIR = join(ROOT, 'data/gate-mitm');

// h1 hop headers the client sends that are illegal inside h2 (or identity).
const DROP_REQ = new Set([
  'connection', 'keep-alive', 'proxy-connection', 'proxy-authorization',
  'transfer-encoding', 'upgrade', 'host', 'te', 'trailer',
]);
const DROP_RES = new Set([
  'connection', 'keep-alive', 'transfer-encoding', 'upgrade',
  'proxy-authenticate', 'proxy-authorization',
]);

const sh = (args, input) => {
  const r = spawnSync('openssl', args, { timeout: 15000, input });
  if (r.status !== 0) throw new Error('openssl ' + args[0] + ': ' + (r.stderr || '').toString().trim());
  return r.stdout;
};

export class GateMitm {
  constructor() {
    const mode = (process.env.YAKGATE_MITM || '').trim();
    this.all = mode === 'all';
    this.hosts = new Set(
      this.all || !mode ? [] : mode.split(',').map(s => s.trim().toLowerCase()).filter(Boolean));
    this._ca = null;
    this._ctx = new Map();      // host -> SecureContext (minted cert)
    this._sess = new Map();     // origin key -> http2.ClientHttp2Session
    // one inner http.Server, fed every client-facing TLSSocket
    this._inner = http.createServer((req, res) => this._relay(req, res));
    this._inner.on('upgrade', (req, sock) => {
      // WebSocket-over-MITM needs an h1 upstream relay (WS can't ride h2).
      // Scaffold: refuse the upgrade rather than hang the client.
      try { sock.destroy(); } catch {}
    });
  }

  get enabled() { return this.all || this.hosts.size > 0; }

  shouldMitm(host) {
    if (!this.enabled || !host) return false;
    host = host.toLowerCase();
    if (this.all) return true;
    for (const h of this.hosts)
      if (host === h || host.endsWith('.' + h)) return true;
    return false;
  }

  // ---- CA + minted certs --------------------------------------------------

  ca() {
    if (this._ca) return this._ca;
    const keyPath = join(DIR, 'ca.key'), crtPath = join(DIR, 'ca.crt');
    if (!existsSync(keyPath) || !existsSync(crtPath)) {
      mkdirSync(DIR, { recursive: true, mode: 0o700 });
      sh(['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '3650', '-nodes',
          '-keyout', keyPath, '-out', crtPath,
          '-subj', '/CN=YakGate Local CA/O=YakMesh',
          '-addext', 'basicConstraints=critical,CA:TRUE',
          '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
    }
    this._ca = { key: readFileSync(keyPath), cert: readFileSync(crtPath) };
    return this._ca;
  }

  caCertPath() { this.ca(); return join(DIR, 'ca.crt'); }

  _ctxFor(host) {
    let ctx = this._ctx.get(host);
    if (ctx) return ctx;
    const ca = this.ca();
    const mint = join(DIR, 'mint');
    mkdirSync(mint, { recursive: true, mode: 0o700 });
    const safe = host.replace(/[^a-z0-9.-]/gi, '_');
    const keyPath = join(mint, safe + '.key');
    const csrPath = join(mint, safe + '.csr');
    const crtPath = join(mint, safe + '.crt');
    if (!existsSync(crtPath)) {
      sh(['req', '-newkey', 'rsa:2048', '-nodes',
          '-keyout', keyPath, '-out', csrPath, '-subj', '/CN=' + host]);
      const extPath = join(mint, safe + '.ext');
      writeFileSync(extPath,
        'subjectAltName=DNS:' + host + '\n' +
        'basicConstraints=critical,CA:FALSE\n' +
        'keyUsage=critical,digitalSignature,keyEncipherment\n' +
        'extendedKeyUsage=serverAuth\n');
      sh(['x509', '-req', '-in', csrPath,
          '-CA', join(DIR, 'ca.crt'), '-CAkey', join(DIR, 'ca.key'),
          '-CAcreateserial', '-days', '825', '-sha256',
          '-extfile', extPath, '-out', crtPath]);
    }
    ctx = { key: readFileSync(keyPath), cert: readFileSync(crtPath) };
    this._ctx.set(host, ctx);
    return ctx;
  }

  // ---- the boundary cut ---------------------------------------------------

  /**
   * Caller has already written the tunnel-established reply (200 / SOCKS
   * granted) and unshifted any pre-read bytes. We hand the socket to a
   * tls.Server minting `host`'s cert; if the client aborts the handshake
   * (untrusted CA), `fallback()` replays `head` into a raw tunnel.
   */
  attach(clientSock, host, port, addrs, fallback) {
    let fell = false;
    const fail = () => {
      if (fell) return; fell = true;
      try { clientSock.removeAllListeners('error'); } catch {}
      fallback();
    };
    const keyCert = (() => { try { return this._ctxFor(host); }
                             catch { fail(); return null; } })();
    if (fell) return;
    // pass key/cert (not a prebuilt SecureContext): Node applies its
    // sigalgs/cipher defaults only when it builds the context itself — a
    // raw SecureContext on OpenSSL 3 negotiates zero sigalgs → alert 40.
    const srv = tls.createServer({
      key: keyCert.key, cert: keyCert.cert,
      ALPNProtocols: ['http/1.1'], // browser side is localhost — h1 is plenty
    });
    srv.on('tlsClientError', fail);
    srv.on('secureConnection', s => {
      s.yakHost = host.toLowerCase(); s.yakPort = port; s.yakAddrs = addrs;
      s.on('error', () => s.destroy());
      this._inner.emit('connection', s);
    });
    srv.emit('connection', clientSock);
    clientSock.once('error', fail);
  }

  // ---- upstream: our TLS, our h2 ------------------------------------------

  _session(host, port, addrs) {
    const key = host + ':' + port;
    let s = this._sess.get(key);
    if (s && !s.destroyed && !s.closed) return s;
    s = http2.connect(`https://${host}:${port}`, {
      settings: { enablePush: false },
      // default TLS: the uniform fingerprint IS the feature — every meshed
      // gate presents the same JA4 upstream.
      // connect to the CONNECT-time vetted addr — re-resolving here would
      // reopen the rebind window publicAddrs closed.
      createConnection: () => tls.connect({
        host: addrs[0], port, servername: host, ALPNProtocols: ['h2'],
      }),
    });
    const drop = () => this._sess.delete(key);
    s.on('error', drop);
    s.on('goaway', drop);
    s.on('close', drop);
    this._sess.set(key, s);
    return s;
  }

  _relay(req, res) {
    const host = (req.headers.host || '').split(':')[0];
    // a request naming a different Host than the CONNECT target never got
    // SSRF-vetted — refuse it rather than smuggle it upstream.
    if (!host || host.toLowerCase() !== req.socket.yakHost)
      { res.writeHead(400); res.end(); return; }
    const sess = this._session(host, req.socket.yakPort || 443,
                               req.socket.yakAddrs || []);
    const port = req.socket.yakPort || 443;
    const hdrs = { ':method': req.method, ':path': req.url, ':scheme': 'https', ':authority': host + (port === 443 ? '' : ':' + port) };
    for (const [k, v] of Object.entries(req.headers))
      if (!DROP_REQ.has(k)) hdrs[k] = v;
    const up = sess.request(hdrs);
    up.on('response', h => {
      const rh = {};
      for (const k in h) if (!k.startsWith(':') && !DROP_RES.has(k)) rh[k] = h[k];
      res.writeHead(h[':status'], rh);
    });
    up.on('error', () => { try { res.destroy(); } catch {} });
    up.pipe(res);
    req.pipe(up);
  }

  summary() {
    return { enabled: this.enabled, mode: this.all ? 'all' : [...this.hosts].join(',') };
  }
}
