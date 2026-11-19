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

import { spawn } from 'node:child_process';
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

// async spawn — spawnSync here would stall the whole event loop (every
// proxied request on the box) for the duration of the mint.
const sh = (args, input) => new Promise((resolve, reject) => {
  const p = spawn('openssl', args, { timeout: 15000 });
  const out = [], err = [];
  p.stdout.on('data', d => out.push(d));
  p.stderr.on('data', d => err.push(d));
  p.on('error', reject);
  p.on('close', code => code === 0
    ? resolve(Buffer.concat(out))
    : reject(new Error('openssl ' + args[0] + ': ' + Buffer.concat(err).toString().trim())));
  if (input) p.stdin.write(input);
  p.stdin.end();
});

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

  async ca() {
    if (this._ca) return this._ca;
    const keyPath = join(DIR, 'ca.key'), crtPath = join(DIR, 'ca.crt');
    if (!existsSync(keyPath) || !existsSync(crtPath)) {
      mkdirSync(DIR, { recursive: true, mode: 0o700 });
      await sh(['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '3650', '-nodes',
          '-keyout', keyPath, '-out', crtPath,
          '-subj', '/CN=YakGate Local CA/O=YakMesh',
          '-addext', 'basicConstraints=critical,CA:TRUE',
          '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
    }
    this._ca = { key: readFileSync(keyPath), cert: readFileSync(crtPath) };
    return this._ca;
  }

  async caCertPath() { await this.ca(); return join(DIR, 'ca.crt'); }

  async _ctxFor(host) {
    let ctx = this._ctx.get(host);
    if (ctx) return ctx;
    const ca = await this.ca();
    const mint = join(DIR, 'mint');
    mkdirSync(mint, { recursive: true, mode: 0o700 });
    const safe = host.replace(/[^a-z0-9.-]/gi, '_');
    const keyPath = join(mint, safe + '.key');
    const csrPath = join(mint, safe + '.csr');
    const crtPath = join(mint, safe + '.crt');
    if (!existsSync(crtPath)) {
      await sh(['req', '-newkey', 'rsa:2048', '-nodes',
          '-keyout', keyPath, '-out', csrPath, '-subj', '/CN=' + host]);
      const extPath = join(mint, safe + '.ext');
      writeFileSync(extPath,
        'subjectAltName=DNS:' + host + '\n' +
        'basicConstraints=critical,CA:FALSE\n' +
        'keyUsage=critical,digitalSignature,keyEncipherment\n' +
        'extendedKeyUsage=serverAuth\n');
      await sh(['x509', '-req', '-in', csrPath,
          '-CA', join(DIR, 'ca.crt'), '-CAkey', join(DIR, 'ca.key'),
          '-CAcreateserial', '-days', '825', '-sha256',
          '-extfile', extPath, '-out', crtPath]);
    }
    // leaf+CA as ONE concatenated PEM: the [a,b] array form makes OpenSSL's
    // key-matching walk the wrong cert (x509 key values mismatch).
    ctx = { key: readFileSync(keyPath),
            cert: Buffer.concat([readFileSync(crtPath),
                                 Buffer.from('\n'), ca.cert]) };
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
  async attach(clientSock, host, port, addrs, fallback) {
    let fell = false;
    const fail = (why) => {
      if (fell) return; fell = true;
      // a silent fallback hides real breakage — degrade, but say why
      console.warn('[gate-mitm] ' + host + ' → raw tunnel: ' + (why || '?'));
      try { clientSock.removeAllListeners('error'); } catch {}
      fallback();
    };
    const keyCert = await this._ctxFor(host).catch(() => null);
    if (!keyCert || fell) { fail('mint'); return; }
    // pass key/cert (not a prebuilt SecureContext): Node applies its
    // sigalgs/cipher defaults only when it builds the context itself — a
    // raw SecureContext on OpenSSL 3 negotiates zero sigalgs → alert 40.
    let srv;
    try {
      srv = tls.createServer({
        key: keyCert.key, cert: keyCert.cert,
        ALPNProtocols: ['http/1.1'], // browser side is localhost — h1 is plenty
      });
    } catch { fail('tlsserver'); return; }   // broken mint → raw tunnel, never a crash
    srv.on('tlsClientError', e => fail('tlsClient ' + (e && e.message)));
    srv.on('secureConnection', s => {
      s.yakHost = host.toLowerCase(); s.yakPort = port; s.yakAddrs = addrs;
      s.on('error', () => s.destroy());
      this._inner.emit('connection', s);
    });
    srv.emit('connection', clientSock);
    clientSock.once('error', e => fail('sock ' + (e && e.message)));
  }

  // ---- upstream: our TLS, our h2 ------------------------------------------

  _session(host, port, addrs) {
    const key = host + ':' + port;
    let s = this._sess.get(key);
    if (s && !s.destroyed && !s.closed) return s;
    s = http2.connect(`https://${host}:${port}`, {
      // Chrome-shaped h2 SETTINGS — the frame itself is a fingerprint.
      settings: {
        headerTableSize: 65536,
        enablePush: false,
        maxConcurrentStreams: 1000,
        initialWindowSize: 6291456,
        maxHeaderListSize: 262144,
      },
      // connect to the CONNECT-time vetted addr — re-resolving here would
      // reopen the rebind window publicAddrs closed. ClientHello shaped to
      // a mainstream browser's form: cipher order, sigalgs, groups.
      createConnection: () => tls.connect({
        host: addrs[0], port, servername: host, ALPNProtocols: ['h2'],
        minVersion: 'TLSv1.2',
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384'
          + ':TLS_CHACHA20_POLY1305_SHA256'
          + ':ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'
          + ':ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
          + ':ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
          + ':ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA'
          + ':AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA',
        sigalgs: 'ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256'
          + ':ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384'
          + ':RSA-PSS+SHA512:RSA+SHA512',
        ecdhCurve: 'X25519:P-256:P-384',
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
