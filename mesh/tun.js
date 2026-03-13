/**
 * YAK-TUN: Adaptive Distributed Mesh Tunneling Protocol
 * (c) 2026 Yakmesh — AGPL-3.0
 * 
 * Provides L2/L3 orchestration between the OS network adapter and the encrypted
 * Yakmesh gossip protocol. Enabling distributed NPU-as-a-Service (NaaS).
 */

import { TRIBHUJ } from '../identity/tribhuj-ratchet.js';
import { ANNEX } from './annex.js';

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
            // 1. Check for wintun.dll or TUN driver
            // 2. Open handle to TUN device
            // 3. Set IP: 10.yak.node (mapping Ternary ID to private space)
            this.active = true;
            return true;
        } catch (err) {
            console.error(`[YAK-TUN ERROR] Interface initialization failed: ${err.message}`);
            return false;
        }
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
        // 1. Verify Trust (Karma/Stability) via Prahari
        const trust = this.security.getTrustLevel(fromNodeId);
        if (trust < 2) { // Minimum 'AWAKENED' status required for tunneling
            this.stats.drops++;
            return;
        }

        // 2. Decapsulate
        const packet = Buffer.from(message.p, 'base64');

        // 3. TODO: Write to OS TUN handle
        this.stats.rx += packet.length;
    }
}
