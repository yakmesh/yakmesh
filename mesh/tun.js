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

const execAsync = promisify(exec);

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

        // Performance stats
        this.stats = {
            rx: 0,
            tx: 0,
            drops: 0,
            latentRetransmit: 0
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

        // sendTo signs + ANNEX-wraps and falls back to relay when the
        // peer has no direct WS session.
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
