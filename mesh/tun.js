/**
 * YAK-TUN: Adaptive Distributed Mesh Tunneling Protocol
 * (c) 2026 Yakmesh — AGPL-3.0
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

        // Performance stats
        this.stats = {
            rx: 0,
            tx: 0,
            drops: 0,
            latentRetransmit: 0
        };
    }

    /**
     * Initialize the virtual TUN/TAP interface.
     * Requires administrative privileges to invoke OS-level drivers (WireGuard wintun).
     */
    async init() {
        console.log(`[YAK-TUN] Initializing virtual interface: ${this.iface}`);
        try {
            if (os.platform() !== 'win32') {
                throw new Error("YAK-TUN currently only supports Windows natively.");
            }

            const wt = await import('../utils/wintun-wrapper.js');

            const adapterHandle = wt.WintunCreateAdapter("YakmeshPool", this.iface, null);
            if (!adapterHandle) throw new Error("WintunCreateAdapter failed. Run as Administrator.");

            const sessionHandle = wt.WintunStartSession(adapterHandle, 0x100000);
            if (!sessionHandle) throw new Error("WintunStartSession failed.");

            this.adapter = adapterHandle;
            this.session = sessionHandle;
            this.wt = wt;

            // Derive deterministic proxy IP from local NodeId (fallback YAK)
            const nodeId = this.mesh?.selfId || "YAK_LOCAL";
            const hash = crypto.createHash('sha256').update(nodeId).digest();
            this.virtualIp = `10.199.${hash[0]}.${hash[1]}`;

            // Allow adapter to spin up in OS before binding IP
            await new Promise(r => setTimeout(r, 1500));
            console.log(`[YAK-TUN] Binding IP ${this.virtualIp} to ${this.iface}...`);
            await execAsync(`netsh interface ipv4 set address name="${this.iface}" static ${this.virtualIp} 255.255.0.0`);

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
     * Asynchronous loop reading packets from the Windows OS TUN adapter
     */
    async _startReadLoop() {
        if (!this.active || !this.wt || !this.session) return;

        const loop = () => {
            if (!this.active) return;

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

                            // OS Packet captured! Inject it into the P2P Mesh engine
                            // Currently broadcasts to all trusted peers if not routing
                            this.stats.rx += len;
                            // TODO: Add L3 routing logic (IP dest -> NodeId mapping)
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
     * Handle incoming packet from the OS network stack.
     * Encapsulates it for the mesh, routing by NodeId (persistent identity).
     * 
     * @param {Buffer} packet Raw packet from OS to be sent into the mesh.
     * @param {string} destinationNodeId Persistent NodeId of the target machine.
     */
    async send(packet, destinationNodeId) {
        if (!this.active) return;

        // TODO: NPU-PrePrediction (Is the link stable enough for this packet?)
        // This is where 117 TOPS are used for traffic shaping.

        // Wrap in ANNEX-encrypted payload
        const peer = this.mesh.getPeer(destinationNodeId);
        if (peer && peer.session) {
            this.mesh._send(peer, 'TUN_PACKET', {
                v: 1,
                p: packet.toString('base64'), // Binary payload
                t: Date.now()
            });
            this.stats.tx += packet.length;
        }
    }

    /**
     * Handle incoming TUN_PACKET from the mesh.
     * Injects it directly back into the OS networking stack.
     * 
     * @param {object} message Decrypted message from ANNEX (network.js)
     * @param {string} fromNodeId Sender identity
     */
    onReceive(message, fromNodeId) {
        // 1. Verify Trust (Karma/Stability) via KarmaTrustModel
        const trustScore = this.security.getTrustLevel(fromNodeId);
        const trustLvl = trustScore && typeof trustScore === 'object' ? trustScore.level : trustScore;
        
        if (trustLvl < 2) { // Minimum 'AWAKENED' status required for tunneling
            this.stats.drops++;
            return;
        }

        // 2. Decapsulate
        const packet = Buffer.from(message.p, 'base64');

        // 3. Write to OS TUN handle
        if (this.active && this.wt && this.session && packet.length > 0) {
            const outPtr = this.wt.WintunAllocateSendPacket(this.session, packet.length);
            if (outPtr) {
                // Use RtlCopyMemory to rapidly move V8 memory straight into Windows Kernel ring buffer
                this.wt.RtlCopyMemory(outPtr, packet, packet.length);
                this.wt.WintunSendPacket(this.session, outPtr);
                this.stats.rx += packet.length;
            }
        }
    }
}
