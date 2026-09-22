/**
 * YAK-TUN: Adaptive Distributed Mesh Tunneling Protocol
 * (c) 2026 Yakmesh — YakMesh-NE-1.0
 * 
 * Provides L2/L3 orchestration between the OS network adapter and the encrypted
 * Yakmesh gossip protocol. Enabling distributed NPU-as-a-Service (NaaS).
 */

import TribhujRatchet from '../identity/tribhuj-ratchet.js';
import Annex from './annex.js';
import { exec } from 'child_process';
import { promisify } from 'util';
import crypto from 'crypto';
import os from 'os';
import dgram from 'node:dgram';

const execAsync = promisify(exec);

// Wire B datagram magic — YKT1
const TUN_MAGIC = Buffer.from('YKT1');
const TUN_PING_MS = 10_000;       // underlay heartbeat per known endpoint
const TUN_STALE_MS = 45_000;      // no pong/decrypt within this → wire down
const TUN_DISCOVER_MS = 15_000;   // LAN presence beacon interval

export class YakTun {
    /**
     * @param {string} ifaceName Name of the virtual adapter (e.g., 'yak0', 'win-yak')
     * @param {*} mesh The core network mesh instance (network.js)
     * @param {*} security The security/trust engine (prahari-mesh.js)
     */
    constructor(ifaceName = 'yak0', mesh, security) {
        this.iface = ifaceName;
        this.mesh = mesh;
        this.security = security;
        this.active = false;

        // Route table for non-direct destinations (multi-hop, announced or
        // passively learned): vIp string -> nodeId. Direct peers don't need
        // an entry — their vIP is recomputed from nodeId on every lookup.
        this.routes = new Map();

        // Wire B (UDP underlay) peer table:
        //   nodeId -> { host, port, wsPort, state:'up'|'down', rttMs,
        //               lastPong, lastRx }
        this.endpoints = new Map();
        this.udpSocket = null;
        this.udpPort = 0;

        // LAN discovery — 'discover' datagrams broadcast on the underlay
        // port, AES-GCM'd under a dialect-derived key so only same-build
        // nodes can read them. Hooks fire on the server layer.
        this._discoverTimer = null;
        this._discoverFirstSeen = new Map();   // nodeId -> first beacon ms
        this.onPeerDiscovered = null;          // (nodeId, wsUrl)
        this.onWireBUp = null;                 // (nodeId)
        this.onWireBDown = null;               // (nodeId)

        // Performance stats
        this.stats = {
            rx: 0,
            tx: 0,
            drops: 0,
            latentRetransmit: 0,
            udpTx: 0,
            udpRx: 0,
            udpDrops: 0,
        };
    }

    /**
     * Deterministic virtual IPv4 for a nodeId — same function every node
     * uses to bind its own adapter, so a peer's address is derivable
     * locally without any lookup service.
     */
    static vIpFor(nodeId) {
        const hash = crypto.createHash('sha256').update(String(nodeId)).digest();
        return `10.199.${hash[0]}.${hash[1]}`;
    }

    /** Deterministic virtual IPv6 (ULA fd99:199::/48). */
    static vIp6For(nodeId) {
        const hash = crypto.createHash('sha256').update(String(nodeId)).digest();
        return `fd99:199:${hash[0].toString(16).padStart(2,"0")}${hash[1].toString(16).padStart(2,"0")}:${hash[2].toString(16).padStart(2,"0")}${hash[3].toString(16).padStart(2,"0")}::1`;
    }

    /**
     * Resolve a virtual-IP destination to a nodeId.
     * 1) Direct peers: recompute vIP from nodeId (authoritative, no table).
     * 2) Announced/learned routes for multi-hop or relay peers.
     */
    routeFor(destIp) {
        if (this.mesh?.peers) {
            for (const [nodeId] of this.mesh.peers) {
                if (YakTun.vIpFor(nodeId) === destIp ||
                    YakTun.vIp6For(nodeId) === destIp) return nodeId;
            }
        }
        return this.routes.get(destIp) || null;
    }

    /** Record an announced or observed route (multi-hop / relay peers). */
    learnRoute(vIp, nodeId) {
        if (vIp && nodeId) this.routes.set(vIp, nodeId);
    }

    // ────────────────────────────────────────────────────────────────
    // Wire B — UDP underlay
    //
    // TUN packets travel as ANNEX-encrypted UDP datagrams to the peer's
    // real endpoint, independent of mesh WS sessions. This is what makes
    // overlay sessions (ws://vIP) safe: the tunnel's carrier is no longer
    // the mesh itself, so no write can recurse into its own encapsulation.
    //
    // Sessions are keyed `tun:<nodeId>` — a separate ANNEX sequence space
    // from the mesh session — and keyed by JHILKE's deterministic pair
    // bootstrap key, so wire B is encrypted from datagram one with zero
    // handshake. (Group-static key; KEM-inherited rekey is a documented
    // next step — CONFIDENTIAL/docs/YAKTUN-DUAL-WIRE.md.)
    // ────────────────────────────────────────────────────────────────

    /**
     * Bind the UDP underlay socket. Called after init() succeeds.
     * @param {number} port UDP port to bind (convention: same number as wsPort)
     */
    async initUnderlay(port) {
        // The socket doubles as the LAN-discovery transport — bind it even
        // when the TUN device itself failed (no admin / no /dev/net/tun);
        // 'data' ops still gate on the interface via injectLocal().
        if (this.udpSocket) return false;
        this.udpPort = port;
        try {
            this.udpSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
            this.udpSocket.on('message', (buf, rinfo) => this._onDatagram(buf, rinfo));
            this.udpSocket.on('error', (err) => {
                console.warn(`[YAK-TUN] UDP underlay error: ${err.message}`);
            });
            await new Promise((resolve, reject) => {
                this.udpSocket.once('error', reject);
                this.udpSocket.bind(port, () => resolve());
            });
            try { this.udpSocket.setBroadcast(true); } catch { }
            this._underlayPingTimer = setInterval(() => this._pingEndpoints(), TUN_PING_MS);
            this._discoverTimer = setInterval(() => this._sendDiscover(), TUN_DISCOVER_MS);
            setTimeout(() => this._sendDiscover(), 1000);
            console.log(`[YAK-TUN] 🟢 UDP underlay listening on :${this.udpPort} (wire B + LAN discovery)`);
            return true;
        } catch (err) {
            console.warn(`[YAK-TUN] UDP underlay bind failed on :${port}: ${err.message}`);
            try { this.udpSocket?.close(); } catch {}
            this.udpSocket = null;
            return false;
        }
    }

    /**
     * Learn a peer's real UDP endpoint. Called from tun:announce gossip and
     * from any authenticated datagram (passive re-learn covers NAT rebinds).
     */
    learnEndpoint(nodeId, host, port, wsPort = 0) {
        if (!nodeId || !host || !port) return;
        const selfId = this._selfNodeId || this.mesh?.identity?.identity?.nodeId;
        if (nodeId === selfId) return; // never learn our own endpoint
        const prev = this.endpoints.get(nodeId);
        this.endpoints.set(nodeId, {
            host, port,
            wsPort: wsPort || prev?.wsPort || 0,
            state: prev?.state || 'down',
            rttMs: prev?.rttMs || 0,
            lastPong: prev?.lastPong || 0,
            lastRx: prev?.lastRx || 0,
        });
        // Probe immediately — don't make the first packets wait a full
        // ping interval for the wire to prove itself.
        if (this.udpSocket && (!prev || prev.host !== host || prev.port !== port)) {
            this._sendDatagram(nodeId, 'hello', {
                wsPort: this._selfWsPort || 0,
                vIp: this.virtualIp,
            });
            this._sendDatagram(nodeId, 'ping', { t: Date.now() });
        }
    }

    // ── LAN discovery ─────────────────────────────────────────────────
    // Same codebase = same dialectSeed = decryptable beacon. A 'discover'
    // datagram carries our real endpoint + vIP; receivers learn the wire-B
    // endpoint directly and surface a dial hint via onPeerDiscovered.
    // Identity is NOT established here — the WS HELLO handshake remains
    // the admission gate; the beacon only proves same-build presence.

    /** Symmetric beacon key: every node on this build shares dialectSeed. */
    _discoveryKey() {
        const seed = this.mesh?.jhilke?.dialectSeed;
        if (!seed) return null;
        return crypto.createHash('sha3-256')
            .update('yaktun-lan:')
            .update(seed)
            .digest();
    }

    /** Limited broadcast + per-interface directed broadcasts. */
    _broadcastAddrs() {
        const addrs = new Set(['255.255.255.255']);
        try {
            for (const list of Object.values(os.networkInterfaces())) {
                for (const i of list || []) {
                    if (i.family !== 'IPv4' || i.internal || !i.netmask) continue;
                    if (i.address.startsWith('10.199.')) continue; // our own vIP iface
                    const a = i.address.split('.').map(Number);
                    const m = i.netmask.split('.').map(Number);
                    if (a.length === 4 && m.length === 4) {
                        addrs.add(a.map((v, j) => (v | (~m[j] & 255))).join('.'));
                    }
                }
            }
        } catch { }
        return [...addrs];
    }

    /** Broadcast one 'discover' beacon on the underlay port. */
    _sendDiscover() {
        const key = this._discoveryKey();
        const selfId = this._selfNodeId || this.mesh?.identity?.identity?.nodeId;
        if (!this.udpSocket || !key || !selfId) return;
        try {
            const iv = crypto.randomBytes(12);
            const c = crypto.createCipheriv('aes-256-gcm', key, iv);
            const ct = Buffer.concat([c.update(JSON.stringify({
                op: 'discover',
                nodeId: selfId,
                wsPort: this._selfWsPort || 0,
                tunPort: this.udpPort || 0,
                vIp: this.virtualIp || null,
                vIp6: this.virtualIpv6 || null,
            }), 'utf8'), c.final()]);
            const blob = Buffer.concat([iv, ct, c.getAuthTag()]);
            const body = Buffer.from(JSON.stringify({
                v: 1, t: Date.now(), k: 'net', d: blob.toString('base64'),
            }), 'utf8');
            const from = Buffer.from(String(selfId), 'utf8');
            const gram = Buffer.concat([TUN_MAGIC, Buffer.from([from.length]), from, body]);
            for (const addr of this._broadcastAddrs()) {
                try { this.udpSocket.send(gram, this.udpPort, addr); } catch { }
            }
            this.stats.udpTx += gram.length;
        } catch { }
    }

    /** Handle a 'net'-keyed beacon datagram. */
    _onDiscover(env, rinfo) {
        const key = this._discoveryKey();
        if (!key || typeof env.d !== 'string') { this.stats.udpDrops++; return; }
        let d;
        try {
            const blob = Buffer.from(env.d, 'base64');
            const dec = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
            dec.setAuthTag(blob.subarray(blob.length - 16));
            d = JSON.parse(Buffer.concat([
                dec.update(blob.subarray(12, blob.length - 16)), dec.final(),
            ]).toString('utf8'));
        } catch { this.stats.udpDrops++; return; } // foreign build — noise
        if (d?.op !== 'discover' || !d.nodeId) return;
        const selfId = this._selfNodeId || this.mesh?.identity?.identity?.nodeId;
        if (d.nodeId === selfId) return; // own broadcast
        const isNew = !this._discoverFirstSeen.has(d.nodeId);
        const firstSeen = this._discoverFirstSeen.get(d.nodeId) ?? Date.now();
        this._discoverFirstSeen.set(d.nodeId, firstSeen);
        if (isNew) {
            console.log(`[YAK-TUN] LAN peer discovered: ${String(d.nodeId).slice(0, 20)} (${rinfo.address}:${d.tunPort || rinfo.port})`);
        }
        // Learn the wire-B endpoint — source addr:port IS their underlay.
        this.learnEndpoint(d.nodeId, rinfo.address, rinfo.port, d.wsPort || 0);
        if (d.vIp) this.learnRoute(d.vIp, d.nodeId);
        if (d.vIp6) this.learnRoute(d.vIp6, d.nodeId);
        const wsUrl = d.wsPort ? `ws://${rinfo.address}:${d.wsPort}` : null;
        this.onPeerDiscovered?.(d.nodeId, wsUrl, firstSeen);
    }

    /**
     * Consume a tun:announce gossip payload. `originHost` is the sender's
     * real IP when we share a transport (connected peer); when the announce
     * arrived multi-hop and carries data.tunHost, that is used instead.
     */
    handleAnnounce(data, originHost) {
        if (!data?.nodeId || !data?.vIp) return;
        const selfId = this._selfNodeId || this.mesh?.identity?.identity?.nodeId;
        if (data.nodeId === selfId) return; // own announce echoed back via gossip
        this.learnRoute(data.vIp, data.nodeId);
        if (data.vIp6) this.learnRoute(data.vIp6, data.nodeId);
        const host = originHost || data.tunHost || null;
        if (host && data.tunPort) {
            this.learnEndpoint(data.nodeId, host, data.tunPort, data.wsPort || 0);
        }
    }

    /**
     * Is wire B proven up for this peer? (Endpoint known AND a datagram —
     * ping reply or any decrypt — seen within the stale window.)
     */
    underlayUp(nodeId) {
        const ep = this.endpoints.get(nodeId);
        if (!ep || ep.state === 'down') return false;
        return (Date.now() - Math.max(ep.lastPong, ep.lastRx)) < TUN_STALE_MS;
    }

    /**
     * Overlay dial target for a peer: `ws://<vIP>:<wsPort>` when wire B is
     * up and the peer announced a WS port. network.js prefers this when
     * dialing known nodeIds — session traffic then rides inside the tunnel.
     */
    overlayEndpointFor(nodeId) {
        if (!this.udpSocket || !this.underlayUp(nodeId)) return null;
        const ep = this.endpoints.get(nodeId);
        const wsPort = ep?.wsPort || 9080;
        return `ws://${YakTun.vIpFor(nodeId)}:${wsPort}`;
    }

    /** Snapshot for status surfaces. */
    underlayStatus() {
        const eps = {};
        for (const [nodeId, ep] of this.endpoints) {
            eps[nodeId.slice(0, 20)] = {
                addr: `${ep.host}:${ep.port}`,
                wsPort: ep.wsPort || null,
                state: this.underlayUp(nodeId) ? 'up' : 'down',
                rttMs: ep.rttMs || null,
            };
        }
        return {
            udpPort: this.udpPort || null,
            listening: !!this.udpSocket,
            peers: eps,
            stats: { udpTx: this.stats.udpTx, udpRx: this.stats.udpRx, udpDrops: this.stats.udpDrops },
        };
    }

    /**
     * ANNEX session for wire B — `tun:<nodeId>` namespace. Creates a
     * JHILKE-bootstrap session lazily; reuses whatever session exists
     * (a future KEM-derived rekey lands here transparently).
     */
    _tunSession(nodeId) {
        const annex = this.mesh?.annex;
        const jhilke = this.mesh?.jhilke;
        if (!annex) return null;
        // Never build sessions to ourselves — own datagrams CAN loop back
        // (broadcast echo, or our tun:announce re-learning our endpoint
        // via gossip), and a self-pair key space is meaningless noise.
        const selfId = this._selfNodeId || this.mesh?.identity?.identity?.nodeId;
        if (nodeId === selfId) return null;
        const key = `tun:${nodeId}`;
        let session = annex.sessions.get(key);
        if (session?.established && !session.isExpired()) return session;
        if (!jhilke) return session || null;
        // Domain-separated re-key of the pair bootstrap key: sorted-pair
        // derivation must see the REAL nodeIds (a 'tun:' prefix would sort
        // differently per side and produce different keys/AAD). Storage is
        // namespaced so wire B gets its own sequence space.
        const pairKey = jhilke.deriveBootstrapKey(nodeId);
        const bk = crypto.createHash('sha3-256')
            .update('yaktun-underlay:')
            .update(pairKey)
            .digest();
        return annex.bootstrapSession(nodeId, bk, key);
    }

    /**
     * Encrypt + send one datagram to a peer's real endpoint.
     * ops: 'data' | 'ping' | 'pong' | 'hello'
     */
    _sendDatagram(nodeId, op, fields = {}) {
        const ep = this.endpoints.get(nodeId);
        if (!this.udpSocket || !ep) return false;
        const session = this._tunSession(nodeId);
        if (!session) return false;
        const selfId = this._selfNodeId || this.mesh?.identity?.identity?.nodeId;
        if (!selfId) return false;
        let d;
        try {
            d = session.encrypt({ op, ...fields });
        } catch { return false; }
        const from = Buffer.from(String(selfId), 'utf8');
        const body = Buffer.from(JSON.stringify({ v: 1, t: Date.now(), d }), 'utf8');
        const head = Buffer.concat([TUN_MAGIC, Buffer.from([from.length]), from]);
        const gram = Buffer.concat([head, body]);
        this.udpSocket.send(gram, ep.port, ep.host);
        this.stats.udpTx += gram.length;
        return true;
    }

    /** Wire-B heartbeat: ping every known endpoint, expire stale wires. */
    _pingEndpoints() {
        const now = Date.now();
        for (const [nodeId, ep] of this.endpoints) {
            this._sendDatagram(nodeId, 'ping', { t: now });
            const alive = (now - Math.max(ep.lastPong, ep.lastRx)) < TUN_STALE_MS;
            const next = alive ? 'up' : 'down';
            if (next !== ep.state) {
                ep.state = next;
                console.log(`[YAK-TUN] wire B ${next} for ${nodeId.slice(0, 20)} (${ep.host}:${ep.port})`);
                if (next === 'up') { try { this.onWireBUp?.(nodeId); } catch { } }
                else { try { this.onWireBDown?.(nodeId); } catch { } }
            }
            // Reap endpoints that have been dead for 10+ minutes and belong
            // to no live session — table stays small, stale entries can't
            // pin a dead wire forever.
            if (!alive && now - Math.max(ep.lastPong, ep.lastRx) > 600_000
                && !this.mesh?.peers?.has(nodeId)) {
                this.endpoints.delete(nodeId);
            }
        }
        // Same TTL for discovery bookkeeping — a peer that vanished gets
        // a fresh first-seen (and fresh dial eligibility) if it returns.
        for (const [nodeId, t] of this._discoverFirstSeen) {
            if (now - t > 600_000 && !this.endpoints.has(nodeId)
                && !this.mesh?.peers?.has(nodeId)) {
                this._discoverFirstSeen.delete(nodeId);
            }
        }
    }

    _onDatagram(buf, rinfo) {
        if (buf.length < 6 || !buf.subarray(0, 4).equals(TUN_MAGIC)) return;
        const fromLen = buf[4];
        if (buf.length < 5 + fromLen) return;
        const fromNodeId = buf.subarray(5, 5 + fromLen).toString('utf8');
        let env;
        try { env = JSON.parse(buf.subarray(5 + fromLen).toString('utf8')); }
        catch { this.stats.udpDrops++; return; }
        if (env?.v !== 1 || !env?.d) { this.stats.udpDrops++; return; }

        // 'net'-keyed datagrams are LAN beacons — same-build broadcast
        // channel, not a pair session. Handled before pair decrypt.
        if (env.k === 'net') { this._onDiscover(env, rinfo); return; }

        // Own datagrams can loop back (broadcast echo, reflected relay) —
        // never build a wire-B session to ourselves.
        const selfId = this._selfNodeId || this.mesh?.identity?.identity?.nodeId;
        if (fromNodeId === selfId) return;

        // Sender claims nodeId in cleartext — the GCM authTag under the
        // pair key is what actually proves it.
        let session = this._tunSession(fromNodeId);
        if (!session) { this.stats.udpDrops++; return; }
        let plain;
        try {
            plain = JSON.parse(session.decrypt(env.d, env.d.sequence));
        } catch (e) {
            // Peer restart resets their send sequence to 0 — our session
            // would reject it as replay forever. The bootstrap key is
            // deterministic, so recreating the session heals instantly.
            // A forged low-seq datagram still fails GCM after recreation.
            if (typeof env.d.sequence === 'number' && env.d.sequence < 16) {
                // Throttle the heal — under build skew every datagram fails
                // GCM, and unthrottled delete+recreate turns a ping burst
                // into a session-creation storm (hundreds/ms observed).
                this._sessionResetAt ||= new Map();
                const lastReset = this._sessionResetAt.get(fromNodeId) || 0;
                if (Date.now() - lastReset < 5000) { this.stats.udpDrops++; return; }
                this._sessionResetAt.set(fromNodeId, Date.now());
                this.mesh?.annex?.sessions.delete(`tun:${fromNodeId}`);
                session = this._tunSession(fromNodeId);
                try {
                    plain = JSON.parse(session.decrypt(env.d, env.d.sequence));
                    console.log(`[YAK-TUN] wire-B session reset for ${fromNodeId.slice(0, 20)} (peer restart)`);
                } catch { this.stats.udpDrops++; return; }
            } else {
                this.stats.udpDrops++;
                return;
            }
        }

        // Authenticated — learn/refresh the endpoint (NAT rebind covered).
        const ep = this.endpoints.get(fromNodeId) || {
            host: rinfo.address, port: rinfo.port, wsPort: 0,
            state: 'down', rttMs: 0, lastPong: 0, lastRx: 0,
        };
        ep.host = rinfo.address;
        ep.port = rinfo.port;
        ep.lastRx = Date.now();
        if (ep.state !== 'up') {
            ep.state = 'up';
            console.log(`[YAK-TUN] wire B up for ${fromNodeId.slice(0, 20)} (${ep.host}:${ep.port})`);
            try { this.onWireBUp?.(fromNodeId); } catch { }
        }
        this.endpoints.set(fromNodeId, ep);
        this.stats.udpRx += buf.length;

        switch (plain.op) {
            case 'data': {
                // Wire-B auth IS the gate — GCM under the pair key proves a
                // same-build, nodeId-bound sender. The karma gate stays on
                // the WS-encap path (v1 semantics unchanged).
                if (typeof plain.p !== 'string') return;
                const packet = Buffer.from(plain.p, 'base64');
                this.learnRoute(YakTun.vIpFor(fromNodeId), fromNodeId);
                this.learnRoute(YakTun.vIp6For(fromNodeId), fromNodeId);
                this.injectLocal(packet);
                break;
            }
            case 'ping':
                this._sendDatagram(fromNodeId, 'pong', { t: plain.t });
                break;
            case 'pong':
                if (typeof plain.t === 'number') {
                    ep.lastPong = Date.now();
                    ep.rttMs = Date.now() - plain.t;
                }
                break;
            case 'hello':
                if (plain.wsPort) ep.wsPort = plain.wsPort;
                if (plain.vIp) this.learnRoute(plain.vIp, fromNodeId);
                this._sendDatagram(fromNodeId, 'hello', {
                    wsPort: this._selfWsPort || 0,
                    vIp: this.virtualIp,
                });
                break;
        }
    }

    /** Clean shutdown — socket + timers. */
    destroy() {
        this.active = false;
        if (this._underlayPingTimer) {
            clearInterval(this._underlayPingTimer);
            this._underlayPingTimer = null;
        }
        if (this._discoverTimer) {
            clearInterval(this._discoverTimer);
            this._discoverTimer = null;
        }
        try { this.udpSocket?.close(); } catch {}
        this.udpSocket = null;
    }

    /**
     * Initialize the virtual TUN/TAP interface.
     * Requires administrative privileges to invoke OS-level drivers (WireGuard wintun).
     */
    async init(nodeIdOverride) {
        console.log(`[YAK-TUN] Initializing virtual interface: ${this.iface}`);
        try {
            const isWin = os.platform() === 'win32';
            const isLinux = os.platform() === 'linux';
            if (!isWin && !isLinux) {
                throw new Error(`YAK-TUN unsupported on ${os.platform()}`);
            }

            // Derive deterministic proxy IP from the real network identity.
            // mesh.selfId does not exist — without an override every node
            // would bind the identical "YAK_LOCAL" address (10.199.60.208).
            const nodeId = nodeIdOverride || "YAK_LOCAL";
            this.virtualIp = YakTun.vIpFor(nodeId);
            this.virtualIpv6 = YakTun.vIp6For(nodeId);

            if (isLinux) return await this._initLinux(nodeId);

            const wt = await import('../utils/wintun-wrapper.js');

            const adapterHandle = wt.WintunCreateAdapter(this.iface, "YakTun", null);
            if (!adapterHandle) throw new Error("WintunCreateAdapter failed. Run as Administrator.");

            const sessionHandle = wt.WintunStartSession(adapterHandle, 0x100000);
            if (!sessionHandle) throw new Error("WintunStartSession failed.");

            this.adapter = adapterHandle;
            this.session = sessionHandle;
            this.wt = wt;

            // Allow adapter to spin up in OS before binding IP
            await new Promise(r => setTimeout(r, 1500));
            console.log(`[YAK-TUN] Binding IP ${this.virtualIp} (v4) and ${this.virtualIpv6} (v6) to ${this.iface}...`);
            try {
                await execAsync(`netsh interface ipv4 set address name="${this.iface}" static ${this.virtualIp} 255.255.0.0`);
            } catch (err) {
                // netsh stderr carries the real reason (access denied = needs
                // Administrator; not found = adapter name mismatch)
                throw new Error(`IPv4 bind failed — ${(err.stderr || err.message).trim()}`);
            }
            try {
                await execAsync(`netsh interface ipv6 add address name="${this.iface}" ${this.virtualIpv6}/64`);
            } catch (err) {
                console.warn(`[YAK-TUN WARN] IPv6 binding failed: ${(err.stderr || err.message).trim()}`);
            }

            this.active = true;
            console.log(`[YAK-TUN] 🟢 Online. OS networking bridge established.`);

            this._startReadLoop();
            return true;
        } catch (err) {
            console.warn(`[YAK-TUN ERROR] Interface initialization skipped: ${err.message}`);
            this.active = false;
            return false;
        }
    }

    /**
     * Linux backend: attach to a persistent /dev/net/tun device.
     * `ip tuntap add dev yak0 mode tun <user>` creates a tun the unprivileged
     * node can open; TUNSETIFF binds our fd to it. IFF_NO_PI keeps packets
     * as raw IP (no 4-byte header) — identical semantics to wintun.
     */
    async _initLinux(nodeId) {
        const fs = await import('fs');
        const koffi = (await import('koffi')).default;
        const user = os.userInfo().username;

        // Create the persistent tun if absent (needs CAP_NET_ADMIN → sudo -n).
        // Failure is non-fatal: the device may already exist.
        try {
            await execAsync(`sudo -n ip tuntap add dev ${this.iface} mode tun user ${user}`);
        } catch { /* exists or no sudo — attach attempt decides honestly */ }

        const TUNSETIFF = 0x400454ca;
        const IFF_TUN = 0x0001, IFF_NO_PI = 0x1000;
        this.tunFd = fs.openSync('/dev/net/tun',
            fs.constants.O_RDWR | fs.constants.O_NONBLOCK);
        const libc = koffi.load('libc.so.6');
        const ioctl = libc.func('int ioctl(int fd, unsigned long req, void *arg)');
        const ifr = Buffer.alloc(40);
        ifr.write(this.iface, 0, 'ascii');
        ifr.writeUInt16LE(IFF_TUN | IFF_NO_PI, 16);
        if (ioctl(this.tunFd, TUNSETIFF, ifr) < 0) {
            fs.closeSync(this.tunFd);
            throw new Error(`TUNSETIFF ${this.iface} failed — device missing or not ours`);
        }
        this.fs = fs;

        // Bind addresses + bring up (sudo -n; failures warn, not fatal).
        // Flush first so stale addresses from prior nodeIds don't linger.
        try {
            await execAsync(`sudo -n ip addr flush dev ${this.iface}`).catch(() => {});
            await execAsync(`sudo -n ip -6 addr flush dev ${this.iface}`).catch(() => {});
            await execAsync(`sudo -n ip addr replace ${this.virtualIp}/16 dev ${this.iface}`);
            await execAsync(`sudo -n ip -6 addr replace ${this.virtualIpv6}/64 dev ${this.iface}`).catch(() => {});
            await execAsync(`sudo -n ip link set dev ${this.iface} up`);
        } catch (err) {
            console.warn(`[YAK-TUN] Address binding incomplete: ${err.message}`);
        }

        this.active = true;
        console.log(`[YAK-TUN] 🟢 Online (linux). ${this.virtualIp} / ${this.virtualIpv6} on ${this.iface}`);
        this._startReadLoop();
        return true;
    }

    /**
     * Asynchronous loop reading packets from the OS TUN adapter
     */
    async _startReadLoop() {
        if (!this.active) return;
        // Backend readiness: Linux attaches tunFd, Windows binds wt+session.
        if (this.tunFd === undefined && (!this.wt || !this.session)) return;

        const loop = () => {
            if (!this.active) return;

            if (this.tunFd !== undefined) { this._drainLinux(); setTimeout(loop, 5); return; }

            // Read until ring buffer is empty
            while (true) {
                // koffi requires arrays for Out pointers when typed as koffi.out(pointer)
                let packetSizeOut = [0];
                const packetPtr = this.wt.WintunReceivePacket(this.session, packetSizeOut);

                if (packetPtr) {
                    const len = packetSizeOut[0];
                    if (len > 0) {
                        try {
                            // Decode C pointer directly to a V8 Buffer
                            const packetBuffer = Buffer.from(this.wt.koffi.decode(packetPtr, 'uint8', len));

                            // Firestorm Firewall & .yak DNS Routing
                            const pr = this._processOutboundPacket(packetBuffer);
                            if (pr.drop) {
                                this.stats.drops++;
                                this.wt.WintunReleaseReceivePacket(this.session, packetPtr);
                                continue;
                            }

                            // OS Packet captured! Route into the P2P mesh engine
                            this.stats.rx += len;
                            this._routeOutbound(packetBuffer);
                        } catch (e) {
                            console.error("[YAK-TUN] Packet read fault:", e);
                        }
                    }
                    // Free the packet in the WinTun ring buffer so driver can write more
                    this.wt.WintunReleaseReceivePacket(this.session, packetPtr);
                } else {
                    // No packets. Back off to avoid spinning the V8 thread.
                    break;
                }
            }

            // ~5ms loop gives extremely low latency without burning CPU
            setTimeout(loop, 5);
        };
        loop();
    }

    /**
     * Linux read drain — nonblocking reads until EAGAIN, then back off.
     */
    _drainLinux() {
        const buf = Buffer.alloc(65535);
        while (true) {
            let n;
            try { n = this.fs.readSync(this.tunFd, buf, 0, buf.length, null); }
            catch (e) {
                if (e.code === 'EAGAIN' || e.code === 'EWOULDBLOCK') break;
                console.error('[YAK-TUN] read fault:', e.message); break;
            }
            if (n <= 0) break;
            const packet = Buffer.from(buf.subarray(0, n));
            const pr = this._processOutboundPacket(packet);
            if (pr.drop) { this.stats.drops++; continue; }
            this.stats.rx += n;
            this._routeOutbound(packet);
        }
    }

    /**
     * Route an OS-originated packet into the mesh.
     * Only virtual-subnet traffic enters the tunnel — anything else is
     * dropped here rather than leaked into gossip. Unresolved subnet
     * destinations broadcast to all peers (receiving OS drops non-local
     * packets naturally — fine for small meshes; revisit with >50 peers).
     */
    _routeOutbound(packet) {
        if (packet.length < 20) return;
        const version = packet[0] >> 4;
        let destStr;
        if (version === 4) {
            const o = packet;
            if (o[16] !== 10 || o[17] !== 199) { this.stats.drops++; return; }
            destStr = `${o[16]}.${o[17]}.${o[18]}.${o[19]}`;
        } else if (version === 6) {
            if (packet.length < 40) return;
            const d = packet.subarray(24, 40);
            // match fd99:199:xxxx:xxxx::1 shape — compare against peer vIp6
            destStr = null; // resolved by peer comparison below
            for (const [nodeId] of this.mesh?.peers || []) {
                const v6 = YakTun.vIp6For(nodeId);
                const exp = YakTun._v6Bytes(v6);
                if (exp && d.equals(exp)) { this.send(packet, nodeId); return; }
            }
            this._broadcast(packet); return;
        } else { this.stats.drops++; return; }

        const nodeId = this.routeFor(destStr);
        if (nodeId) this.send(packet, nodeId);
        else this._broadcast(packet);
    }

    static _v6Bytes(addr) {
        try {
            const parts = addr.split('::');
            const head = parts[0].split(':').filter(Boolean).map(h => parseInt(h, 16));
            const tail = (parts[1] || '').split(':').filter(Boolean).map(h => parseInt(h, 16));
            const words = [...head, ...Array(8 - head.length - tail.length).fill(0), ...tail];
            if (words.length !== 8) return null;
            const b = Buffer.alloc(16);
            words.forEach((w, i) => b.writeUInt16BE(w, i * 2));
            return b;
        } catch { return null; }
    }

    /** Send a packet to every connected peer (unresolved destination). */
    _broadcast(packet) {
        if (!this.mesh?.peers) return;
        for (const [nodeId] of this.mesh.peers) this.send(packet, nodeId);
    }

    /**
     * Handle incoming packet from the OS network stack.
     * Encapsulates it for the mesh, routing by NodeId (persistent identity).
     *
     * @param {Buffer} packet Raw packet from OS to be sent into the mesh.
     * @param {string} destinationNodeId Persistent NodeId of the target machine.
     */
    async send(packet, destinationNodeId) {
        if (!this.active || !this.mesh?.sendTo) return;

        // TODO: NPU-PrePrediction (Is the link stable enough for this packet?)
        // This is where 117 TOPS are used for traffic shaping.

        // Wire B first: real-endpoint UDP datagram, no mesh session needed.
        // Wire stays eligible while 'up' or freshly learned — the ping loop
        // marks it 'down' only after a full stale window of silence.
        const ep = this.endpoints.get(destinationNodeId);
        if (this.udpSocket && ep && ep.state !== 'down') {
            if (this._sendDatagram(destinationNodeId, 'data', {
                p: packet.toString('base64'),
            })) {
                this.stats.tx += packet.length;
                return;
            }
        }

        // Fallback: WS-encap — sendTo signs + ANNEX-wraps and falls back
        // to relay when the peer has no direct WS session. TUN_PACKET must
        // never ride an overlay socket (recursion) — sendTo enforces that.
        this.mesh.sendTo(destinationNodeId, {
            type: 'TUN_PACKET',
            v: 1,
            p: packet.toString('base64'), // Binary payload
            t: Date.now()
        });
        this.stats.tx += packet.length;
    }

    /**
     * Handle incoming TUN_PACKET from the mesh.
     * Injects it directly back into the OS networking stack.
     * 
     * @param {object} message Decrypted message from ANNEX (network.js)
     * @param {string} fromNodeId Sender identity
     */
    onReceive(message, fromNodeId) {
        // 1. Verify Trust (Karma/Stability) via KarmaTrustModel.
        // Gate = SEEKING (1): peer must be DOKO-verified on an ANNEX channel.
        // AWAKENED (2) requires a mesh quorum of 3 — unreachable on a
        // 2-node LAN tunnel, which is exactly this feature's use case.
        // UNTRUSTED (0) peers still cannot inject packets into the OS.
        const trustScore = this.security.getTrustLevel(fromNodeId);
        const trustLvl = trustScore && typeof trustScore === 'object' ? trustScore.level : trustScore;

        if (trustLvl < 1) {
            this.stats.drops++;
            return;
        }

        // 1b. Passive route learn — the sender's vIP is deterministic
        this.learnRoute(YakTun.vIpFor(fromNodeId), fromNodeId);
        this.learnRoute(YakTun.vIp6For(fromNodeId), fromNodeId);

        // 2. Decapsulate
        const packet = Buffer.from(message.p, 'base64');

        // 3. Write to OS TUN handle
        this.injectLocal(packet);
    }

    /**
     * Injects a raw packet directly into the local OS network stack.
     * @param {Buffer} packet 
     */
    injectLocal(packet) {
        if (this.active && this.tunFd !== undefined && packet.length > 0) {
            try { this.fs.writeSync(this.tunFd, packet); } catch {}
            return;
        }
        if (this.active && this.wt && this.session && packet.length > 0) {
            const outPtr = this.wt.WintunAllocateSendPacket(this.session, packet.length);
            if (outPtr) {
                this.wt.RtlCopyMemory(outPtr, packet, packet.length);
                this.wt.WintunSendPacket(this.session, outPtr);
                // Don't log RX twice
            }
        }
    }

    /**
     * Firestorm Defense Grid & DNS Interceptor
     */
    _processOutboundPacket(packet) {
        if (packet.length < 20) return { forward: true };

        const version = packet[0] >> 4;
        
        // Pass IPv6 through directly for now so we don't drop the new deterministic routing!
        if (version === 6) return { forward: true }; 
        if (version !== 4) return { drop: true }; // Drop everything else

        const ihl = packet[0] & 0x0F;
        const headerLength = ihl * 4;
        const protocol = packet[9]; // 6=TCP, 17=UDP
        
        if (protocol === 6 && packet.length >= headerLength + 4) {
            const dstPort = packet.readUInt16BE(headerLength + 2);
            // Firestorm: Drop Windows scanning
            if ([135, 137, 138, 139, 445, 3389].includes(dstPort)) return { drop: true };
        } else if (protocol === 17 && packet.length >= headerLength + 8) {
            const dstPort = packet.readUInt16BE(headerLength + 2);
            const udpLength = packet.readUInt16BE(headerLength + 4);
            
            if ([135, 137, 138, 139].includes(dstPort)) return { drop: true };

            // .yak DNS Interceptor
            if (dstPort === 53 && packet.length >= headerLength + 8) {
                const dnsPayload = packet.slice(headerLength + 8, headerLength + udpLength);
                try {
                    const dnsPacket = require('dns-packet');
                    const query = dnsPacket.decode(dnsPayload);
                    if (query.type === 'query' && query.questions.length > 0) {
                        const question = query.questions[0];
                        if (question.name.endsWith('.yak')) {
                            const baseName = question.name.replace('.yak', '');
                            const hash = require('crypto').createHash('sha256').update(baseName).digest();
                            const resolvedIp = `10.199.${hash[0]}.${hash[1]}`;
                            
                            const responsePayload = dnsPacket.encode({
                                type: 'response',
                                id: query.id,
                                flags: 0x8180,
                                questions: query.questions,
                                answers: [{type: 'A', class: 'IN', name: question.name, ttl: 300, data: resolvedIp}]
                            });

                            const srcIp = packet.slice(12, 16);
                            const dstIp = packet.slice(16, 20);
                            const srcPortRaw = packet.readUInt16BE(headerLength);
                            
                            const udpHeader = Buffer.alloc(8);
                            udpHeader.writeUInt16BE(53, 0); 
                            udpHeader.writeUInt16BE(srcPortRaw, 2);
                            udpHeader.writeUInt16BE(8 + responsePayload.length, 4); 
                            udpHeader.writeUInt16BE(0, 6);

                            const ipHeader = Buffer.from(packet.slice(0, headerLength));
                            dstIp.copy(ipHeader, 12);
                            srcIp.copy(ipHeader, 16);
                            ipHeader.writeUInt16BE(headerLength + udpHeader.length + responsePayload.length, 2); 
                            
                            ipHeader.writeUInt16BE(0, 10);
                            let sum = 0;
                            for (let i = 0; i < ipHeader.length; i += 2) sum += ipHeader.readUInt16BE(i);
                            while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
                            ipHeader.writeUInt16BE(~sum & 0xFFFF, 10);

                            const forgedResponse = Buffer.concat([ipHeader, udpHeader, responsePayload]);
                            this.injectLocal(forgedResponse);
                            
                            return { drop: true }; // Synthesized locally!
                        }
                    }
                } catch(e) {}
            }
        }
        return { forward: true };
    }
}
