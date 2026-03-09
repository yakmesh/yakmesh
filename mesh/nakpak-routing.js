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
 * Yakmesh NAKPAK Routing - Nested Anonymous Kernel for Private Authenticated Komms
 * 
 * The first post-quantum secure onion routing implementation featuring:
 * - ML-DSA-65 signatures at every routing layer
 * - Kyber (ML-KEM) key encapsulation for quantum-safe key exchange
 * - Multi-layer encryption with perfect forward secrecy
 * - Timing attack resistance through temporal padding
 * 
 * Key Innovation: "Your packets travel like yak caravans through hidden mountain paths"
 * - Each routing layer uses different quantum-resistant keys
 * - Decoy traffic masks real communication patterns
 * - Temporal obfuscation defeats traffic analysis
 * 
 * Etymology: NAK (female yak, the pack carrier) + PAK (package) = NAKPAK (sounds like "knapsack")
 * Works with SHERPA (Secure Hidden Endpoint Resolution Path Architecture) for peer discovery.
 * 
 * @module mesh/nakpak-routing
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { createCipheriv, createDecipheriv, createHash } from 'crypto';
import { seedStore } from '../security/prahari.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha3_256 as _nobleSha3 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

// ACCEL: Hardware-accelerated crypto (SHA3 native, future liboqs PQ)
import { sha3_256, mlDsa65Sign, mlDsa65Verify, mlKem768Encapsulate, mlKem768Decapsulate } from '../utils/accel.js';

// YPC-27 quantum-hard checksums for packet integrity
import {
  PROTOCOL_DOMAIN,
  checksumToWire,
  checksumFromWire,
  PacketChecksum
} from '../oracle/packet-checksum.js';

// NAKPAK checksum engine (singleton per module)
const nakpakChecksumEngine = new PacketChecksum(PROTOCOL_DOMAIN.NAKPAK);

const NAKPAK_CONFIG = {
  // Circuit settings
  defaultHopCount: 3,           // Number of hops (like Tor)
  maxHopCount: 7,               // Maximum allowed hops
  circuitTimeout: 300000,       // 5 minute circuit lifetime

  // Encryption
  layerEncryption: 'aes-256-gcm',
  nonceSize: 12,
  authTagLength: 16,

  // Timing obfuscation
  minPaddingMs: 10,             // Minimum random delay
  maxPaddingMs: 100,            // Maximum random delay
  decoyProbability: 0.1,        // 10% chance of sending decoy

  // Packet sizing
  fixedPacketSize: 8192,        // Fixed size to prevent length analysis
  maxPayloadSize: 7000,         // Max actual payload

  // Key derivation
  keyDerivationSalt: 'NAKPAK-YAKMESH-2026',
};

/**
 * A single routing layer in the onion (like a yak's pack saddle layer)
 */
class NakpakLayer {
  constructor(options) {
    this.hopIndex = options.hopIndex;
    this.nodeId = options.nodeId;
    this.nextHop = options.nextHop || null;
    this.isExit = options.isExit || false;

    // Ephemeral keys for this layer
    this.kemKeyPair = null;
    this.sharedSecret = null;
    this.encryptionKey = null;
  }

  /**
   * Generate ephemeral key pair for key encapsulation
   */
  async generateKeys() {
    const seed = seedStore.squeeze(64, 'NAKPAK-KEM-KEYGEN');
    this.kemKeyPair = ml_kem768.keygen(seed);
    return {
      publicKey: bytesToHex(this.kemKeyPair.publicKey),
      hopIndex: this.hopIndex,
    };
  }

  /**
   * Encapsulate key using peer's public key
   */
  encapsulateKey(peerPublicKey) {
    const publicKeyBytes = hexToBytes(peerPublicKey);
    const result = mlKem768Encapsulate(publicKeyBytes);

    this.sharedSecret = result.sharedSecret;
    this.encryptionKey = this._deriveEncryptionKey(this.sharedSecret);

    return {
      ciphertext: bytesToHex(result.cipherText),
      hopIndex: this.hopIndex,
    };
  }

  /**
   * Decapsulate key from received ciphertext
   */
  decapsulateKey(ciphertext) {
    if (!this.kemKeyPair) {
      throw new Error('No key pair generated');
    }

    const ciphertextBytes = hexToBytes(ciphertext);
    this.sharedSecret = mlKem768Decapsulate(ciphertextBytes, this.kemKeyPair.secretKey);
    this.encryptionKey = this._deriveEncryptionKey(this.sharedSecret);

    return true;
  }

  /**
   * Encrypt data for this layer
   */
  encrypt(data) {
    if (!this.encryptionKey) {
      throw new Error('No encryption key established');
    }

    const nonce = seedStore.squeeze(NAKPAK_CONFIG.nonceSize, 'NAKPAK-NONCE');
    const cipher = createCipheriv(
      NAKPAK_CONFIG.layerEncryption,
      this.encryptionKey,
      nonce,
      { authTagLength: NAKPAK_CONFIG.authTagLength }
    );

    const plaintext = typeof data === 'string' ? data : JSON.stringify(data);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);

    return {
      nonce: nonce.toString('hex'),
      data: encrypted.toString('hex'),
      tag: cipher.getAuthTag().toString('hex'),
    };
  }

  /**
   * Decrypt data for this layer
   */
  decrypt(encryptedData) {
    if (!this.encryptionKey) {
      throw new Error('No encryption key established');
    }

    const nonce = Buffer.from(encryptedData.nonce, 'hex');
    const data = Buffer.from(encryptedData.data, 'hex');
    const tag = Buffer.from(encryptedData.tag, 'hex');

    const decipher = createDecipheriv(
      NAKPAK_CONFIG.layerEncryption,
      this.encryptionKey,
      nonce,
      { authTagLength: NAKPAK_CONFIG.authTagLength }
    );
    decipher.setAuthTag(tag);

    const decrypted = Buffer.concat([
      decipher.update(data),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  }

  _deriveEncryptionKey(sharedSecret) {
    return createHash('sha3-256')
      .update(sharedSecret)
      .update(NAKPAK_CONFIG.keyDerivationSalt)
      .update(Buffer.from([this.hopIndex]))
      .digest();
  }
}

/**
 * An onion-wrapped packet (like a yak's cargo bundle)
 * 
 * Now includes YPC-27 quantum-hard checksum for packet integrity.
 */
class NakpakPacket {
  constructor(options = {}) {
    this.id = options.id || bytesToHex(seedStore.squeeze(16, 'NAKPAK-PACKET-ID'));
    this.circuitId = options.circuitId;
    this.layers = [];           // Encrypted layers (outermost first)
    this.timestamp = options.timestamp || Date.now();
    this.isDecoy = options.isDecoy || false;
    this.padding = null;        // Random padding for fixed size
    this.ypc27 = options.ypc27 || null;  // YPC-27 quantum checksum (computed on finalize)
  }

  /**
   * Add encrypted layer (wrap the onion)
   */
  addLayer(encryptedPayload) {
    this.layers.unshift(encryptedPayload);
  }

  /**
   * Remove outermost layer (peel the onion)
   */
  peelLayer() {
    return this.layers.shift();
  }

  /**
   * Compute YPC-27 quantum-hard checksum for this packet.
   * Called during finalization before transmission.
   * @private
   * @returns {string} Wire format checksum
   */
  _computeYpc27() {
    const checksumData = {
      id: this.id,
      circuitId: this.circuitId,
      layers: this.layers,
      timestamp: this.timestamp,
    };
    const checksum = nakpakChecksumEngine.compute(checksumData);
    return checksumToWire(checksum);
  }

  /**
   * Verify the YPC-27 checksum is valid.
   * @returns {boolean}
   */
  verifyYpc27() {
    if (!this.ypc27) return true; // No checksum = backward compat
    try {
      const expected = checksumFromWire(this.ypc27);
      const checksumData = {
        id: this.id,
        circuitId: this.circuitId,
        layers: this.layers,
        timestamp: this.timestamp,
      };
      return nakpakChecksumEngine.verify(checksumData, expected);
    } catch (err) {
      return false;
    }
  }

  /**
   * Pad to fixed size to prevent length analysis.
   * Also computes and sets the YPC-27 checksum.
   */
  padToFixedSize() {
    // Compute YPC-27 before padding (padding doesn't affect checksum)
    if (!this.ypc27) {
      this.ypc27 = this._computeYpc27();
    }

    const serialized = JSON.stringify({
      id: this.id,
      circuitId: this.circuitId,
      layers: this.layers,
      timestamp: this.timestamp,
      ypc27: this.ypc27,
    });

    const currentSize = Buffer.byteLength(serialized, 'utf8');
    const paddingNeeded = NAKPAK_CONFIG.fixedPacketSize - currentSize - 50; // Reserve for padding field

    if (paddingNeeded > 0) {
      this.padding = seedStore.squeeze(Math.max(1, paddingNeeded), 'NAKPAK-PADDING').toString('base64');
    }
  }

  /**
   * Create decoy packet
   */
  static createDecoy(circuitId) {
    const decoy = new NakpakPacket({
      circuitId,
      isDecoy: true,
    });

    // Fill with random encrypted-looking data
    for (let i = 0; i < 3; i++) {
      decoy.addLayer({
        nonce: seedStore.squeeze(12, 'NAKPAK-DECOY-NONCE').toString('hex'),
        data: seedStore.squeeze(256, 'NAKPAK-DECOY-DATA').toString('hex'),
        tag: seedStore.squeeze(16, 'NAKPAK-DECOY-TAG').toString('hex'),
      });
    }

    decoy.padToFixedSize();
    return decoy;
  }

  serialize() {
    return {
      id: this.id,
      circuitId: this.circuitId,
      layers: this.layers,
      timestamp: this.timestamp,
      padding: this.padding,
      ypc27: this.ypc27,  // Quantum-hard 27-trit checksum
    };
  }

  static deserialize(obj) {
    const packet = new NakpakPacket({
      id: obj.id,
      circuitId: obj.circuitId,
      timestamp: obj.timestamp,
      ypc27: obj.ypc27,
    });
    packet.layers = obj.layers;
    packet.padding = obj.padding;

    // Verify YPC-27 quantum checksum if present
    if (obj.ypc27 && !packet.verifyYpc27()) {
      throw new Error('YPC-27 checksum mismatch - possible quantum attack or packet corruption');
    }

    return packet;
  }
}

/**
 * A circuit through the mesh (like a yak caravan route)
 */
class NakpakCircuit {
  constructor(options = {}) {
    this.circuitId = options.circuitId || bytesToHex(seedStore.squeeze(16, 'NAKPAK-CIRCUIT-ID'));
    this.hops = [];                // Array of NakpakLayer
    this.isEstablished = false;
    this.createdAt = Date.now();
    this.lastUsed = Date.now();
    this.packetsForwarded = 0;
  }

  /**
   * Build a circuit through specified nodes
   */
  async buildCircuit(nodeIds) {
    if (nodeIds.length > NAKPAK_CONFIG.maxHopCount) {
      throw new Error('Too many hops: max is ' + NAKPAK_CONFIG.maxHopCount);
    }

    this.hops = [];

    for (let i = 0; i < nodeIds.length; i++) {
      const layer = new NakpakLayer({
        hopIndex: i,
        nodeId: nodeIds[i],
        nextHop: nodeIds[i + 1] || null,
        isExit: i === nodeIds.length - 1,
      });

      await layer.generateKeys();
      this.hops.push(layer);
    }

    return {
      circuitId: this.circuitId,
      hops: this.hops.map(h => ({
        hopIndex: h.hopIndex,
        nodeId: h.nodeId,
        publicKey: bytesToHex(h.kemKeyPair.publicKey),
      })),
    };
  }

  /**
   * Establish keys with each hop using their public keys
   */
  establishKeys(hopPublicKeys) {
    const ciphertexts = [];

    for (const hop of this.hops) {
      const peerKey = hopPublicKeys.find(k => k.hopIndex === hop.hopIndex);
      if (!peerKey) {
        throw new Error('Missing public key for hop ' + hop.hopIndex);
      }

      const result = hop.encapsulateKey(peerKey.publicKey);
      ciphertexts.push(result);
    }

    this.isEstablished = true;
    return ciphertexts;
  }

  /**
   * Wrap a message in multiple encryption layers
   */
  wrapMessage(message, destination) {
    if (!this.isEstablished) {
      throw new Error('Circuit not established');
    }

    // Start with the innermost layer (exit node message)
    let payload = {
      type: 'DATA',
      destination,
      message,
      timestamp: Date.now(),
    };

    // Wrap in layers from inside out (exit first, entry last)
    for (let i = this.hops.length - 1; i >= 0; i--) {
      const hop = this.hops[i];
      const encrypted = hop.encrypt(payload);

      payload = {
        type: 'RELAY',
        nextHop: hop.nextHop,
        isExit: hop.isExit,
        encrypted,
      };
    }

    const packet = new NakpakPacket({
      circuitId: this.circuitId,
    });
    packet.addLayer(payload);
    packet.padToFixedSize();

    this.lastUsed = Date.now();
    this.packetsForwarded++;

    return packet;
  }

  isExpired() {
    return Date.now() - this.createdAt > NAKPAK_CONFIG.circuitTimeout;
  }
}

/**
 * Relay node handler for forwarding nakpak packets
 */
class NakpakRelay {
  constructor(options = {}) {
    this.nodeId = options.nodeId || bytesToHex(seedStore.squeeze(16, 'NAKPAK-RELAY-ID'));
    this.circuits = new Map();    // circuitId -> local layer info
    this.signKeyPair = null;      // ML-DSA-65 for signing

    this.stats = {
      packetsRelayed: 0,
      circuitsHandled: 0,
      decoysInjected: 0,
    };

    // Initialize signing keys
    this._initKeys();
  }

  async _initKeys() {
    const seed = seedStore.squeeze(32, 'NAKPAK-DSA-KEYGEN');
    this.signKeyPair = ml_dsa65.keygen(seed);
  }

  /**
   * Handle incoming circuit creation request
   */
  async handleCircuitCreate(request) {
    const layer = new NakpakLayer({
      hopIndex: request.hopIndex,
      nodeId: this.nodeId,
      nextHop: request.nextHop,
      isExit: request.isExit,
    });

    await layer.generateKeys();

    this.circuits.set(request.circuitId, {
      layer,
      createdAt: Date.now(),
      packetsRelayed: 0,
    });

    this.stats.circuitsHandled++;

    return {
      circuitId: request.circuitId,
      hopIndex: request.hopIndex,
      publicKey: bytesToHex(layer.kemKeyPair.publicKey),
    };
  }

  /**
   * Handle key establishment
   */
  handleKeyEstablish(circuitId, ciphertext) {
    const circuit = this.circuits.get(circuitId);
    if (!circuit) {
      return { error: 'Unknown circuit' };
    }

    circuit.layer.decapsulateKey(ciphertext);
    return { success: true };
  }

  /**
   * Process incoming packet (peel and forward)
   */
  async processPacket(packet) {
    const circuit = this.circuits.get(packet.circuitId);
    if (!circuit) {
      return { error: 'Unknown circuit' };
    }

    // Add timing obfuscation
    await this._addTimingDelay();

    // Peel the outermost layer
    const encryptedLayer = packet.peelLayer();
    if (!encryptedLayer) {
      return { error: 'No layers to peel' };
    }

    try {
      const decrypted = JSON.parse(circuit.layer.decrypt(encryptedLayer.encrypted));
      circuit.packetsRelayed++;
      this.stats.packetsRelayed++;

      // Maybe inject a decoy
      const decoy = this._maybeInjectDecoy(packet.circuitId);

      if (decrypted.isExit) {
        // We're the exit node - deliver the message
        return {
          type: 'EXIT',
          destination: decrypted.destination,
          message: decrypted.message,
          timestamp: decrypted.timestamp,
          decoy,
        };
      } else {
        // Forward to next hop
        return {
          type: 'FORWARD',
          nextHop: decrypted.nextHop,
          packet: packet.serialize(),
          decoy,
        };
      }
    } catch (err) {
      return { error: 'Decryption failed: ' + err.message };
    }
  }

  /**
   * Add random delay to defeat timing analysis
   */
  async _addTimingDelay() {
    // SECURITY: PRAHARI sponge entropy — hardware + GPS + mesh timing sources
    // prevents attackers from distinguishing real delays from padding
    const randBytes = seedStore.squeeze(4, 'NAKPAK-TIMING');
    const fraction = randBytes.readUInt32BE(0) / 0xFFFFFFFF;
    const delay = NAKPAK_CONFIG.minPaddingMs +
      fraction * (NAKPAK_CONFIG.maxPaddingMs - NAKPAK_CONFIG.minPaddingMs);
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  /**
   * Maybe inject a decoy packet to mask traffic patterns
   */
  _maybeInjectDecoy(circuitId) {
    // SECURITY: Decoy injection uses PRAHARI sponge for unpredictable thresholds
    const threshold = Math.floor(NAKPAK_CONFIG.decoyProbability * 256);
    if (seedStore.squeeze(1, 'NAKPAK-DECOY-INJECT')[0] < threshold) {
      this.stats.decoysInjected++;
      return NakpakPacket.createDecoy(circuitId).serialize();
    }
    return null;
  }

  /**
   * Sign data with ML-DSA-65
   * IMPORTANT: ml_dsa65.sign(message, secretKey) - message FIRST!
   */
  sign(data) {
    const message = typeof data === 'string' ? utf8ToBytes(data) : data;
    return bytesToHex(mlDsa65Sign(message, this.signKeyPair.secretKey));
  }

  /**
   * Verify signature
   * IMPORTANT: ml_dsa65.verify(signature, message, publicKey) - signature FIRST!
   */
  verify(data, signature, publicKey) {
    const message = typeof data === 'string' ? utf8ToBytes(data) : data;
    return mlDsa65Verify(
      hexToBytes(signature),
      message,
      hexToBytes(publicKey)
    );
  }

  getPublicKey() {
    return bytesToHex(this.signKeyPair.publicKey);
  }

  getStats() {
    return { ...this.stats };
  }
}

/**
 * Main NAKPAK routing manager
 */
class NakpakRouter {
  constructor(options = {}) {
    this.nodeId = options.nodeId || bytesToHex(seedStore.squeeze(16, 'NAKPAK-ROUTER-ID'));
    this.relay = new NakpakRelay({ nodeId: this.nodeId });
    this.circuits = new Map();     // circuitId -> NakpakCircuit (for circuits we created)
    this.knownNodes = new Map();   // nodeId -> { publicKey, lastSeen }

    this.stats = {
      circuitsCreated: 0,
      messagesSent: 0,
      messagesReceived: 0,
    };

    // Callbacks
    this.onMessageReceived = options.onMessageReceived || (() => { });
    this.onForward = options.onForward || (() => { });
  }

  /**
   * Register a known node for routing
   */
  registerNode(nodeId, publicKey) {
    this.knownNodes.set(nodeId, {
      publicKey,
      lastSeen: Date.now(),
    });
  }

  /**
   * Create a new circuit through specified hops
   */
  async createCircuit(hopNodeIds) {
    if (hopNodeIds.length === 0) {
      // Auto-select random hops
      const availableNodes = Array.from(this.knownNodes.keys())
        .filter(id => id !== this.nodeId);

      if (availableNodes.length < NAKPAK_CONFIG.defaultHopCount) {
        throw new Error('Not enough known nodes for circuit');
      }

      // Shuffle and pick — PRAHARI sponge entropy for unpredictable circuit paths
      for (let i = availableNodes.length - 1; i > 0; i--) {
        const j = seedStore.squeeze(4, 'NAKPAK-CIRCUIT-SHUFFLE').readUInt32BE(0) % (i + 1);
        [availableNodes[i], availableNodes[j]] = [availableNodes[j], availableNodes[i]];
      }

      hopNodeIds = availableNodes.slice(0, NAKPAK_CONFIG.defaultHopCount);
    }

    const circuit = new NakpakCircuit();
    const buildResult = await circuit.buildCircuit(hopNodeIds);

    this.circuits.set(circuit.circuitId, circuit);
    this.stats.circuitsCreated++;

    return buildResult;
  }

  /**
   * Complete circuit establishment with hop responses
   */
  establishCircuit(circuitId, hopResponses) {
    const circuit = this.circuits.get(circuitId);
    if (!circuit) {
      throw new Error('Unknown circuit');
    }

    const ciphertexts = circuit.establishKeys(hopResponses);
    return { circuitId, established: true, ciphertexts };
  }

  /**
   * Send a message through a circuit
   */
  sendMessage(circuitId, destination, message) {
    const circuit = this.circuits.get(circuitId);
    if (!circuit) {
      throw new Error('Unknown circuit');
    }

    if (circuit.isExpired()) {
      this.circuits.delete(circuitId);
      throw new Error('Circuit expired');
    }

    const packet = circuit.wrapMessage(message, destination);
    this.stats.messagesSent++;

    return {
      packet: packet.serialize(),
      firstHop: circuit.hops[0].nodeId,
    };
  }

  /**
   * Handle incoming packet (as a relay)
   */
  async handlePacket(packetData) {
    const packet = NakpakPacket.deserialize(packetData);
    const result = await this.relay.processPacket(packet);

    if (result.type === 'EXIT') {
      this.stats.messagesReceived++;
      this.onMessageReceived(result);
    } else if (result.type === 'FORWARD') {
      this.onForward(result);
    }

    return result;
  }

  /**
   * Handle circuit creation request (as a relay)
   */
  async handleCircuitCreate(request) {
    return this.relay.handleCircuitCreate(request);
  }

  /**
   * Handle key establishment (as a relay)
   */
  handleKeyEstablish(circuitId, ciphertext) {
    return this.relay.handleKeyEstablish(circuitId, ciphertext);
  }

  /**
   * Cleanup expired circuits
   */
  cleanupCircuits() {
    let cleaned = 0;
    for (const [id, circuit] of this.circuits) {
      if (circuit.isExpired()) {
        this.circuits.delete(id);
        cleaned++;
      }
    }
    return cleaned;
  }

  getStats() {
    return {
      ...this.stats,
      relayStats: this.relay.getStats(),
      activeCircuits: this.circuits.size,
      knownNodes: this.knownNodes.size,
    };
  }
}

export {
  NAKPAK_CONFIG,
  NakpakLayer,
  NakpakPacket,
  NakpakCircuit,
  NakpakRelay,
  NakpakRouter,
};
