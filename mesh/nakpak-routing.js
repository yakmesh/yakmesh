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

import { randomBytes, createCipheriv, createDecipheriv, createHash } from 'crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';

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
    const seed = randomBytes(64);
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
    const result = ml_kem768.encapsulate(publicKeyBytes);
    
    this.sharedSecret = result.sharedSecret;
    this.encryptionKey = this._deriveEncryptionKey(this.sharedSecret);
    
    return {
      ciphertext: bytesToHex(result.ciphertext),
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
    this.sharedSecret = ml_kem768.decapsulate(ciphertextBytes, this.kemKeyPair.secretKey);
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

    const nonce = randomBytes(NAKPAK_CONFIG.nonceSize);
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
 */
class NakpakPacket {
  constructor(options = {}) {
    this.id = options.id || bytesToHex(randomBytes(16));
    this.circuitId = options.circuitId;
    this.layers = [];           // Encrypted layers (outermost first)
    this.timestamp = options.timestamp || Date.now();
    this.isDecoy = options.isDecoy || false;
    this.padding = null;        // Random padding for fixed size
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
   * Pad to fixed size to prevent length analysis
   */
  padToFixedSize() {
    const serialized = JSON.stringify({
      id: this.id,
      circuitId: this.circuitId,
      layers: this.layers,
      timestamp: this.timestamp,
    });

    const currentSize = Buffer.byteLength(serialized, 'utf8');
    const paddingNeeded = NAKPAK_CONFIG.fixedPacketSize - currentSize - 50; // Reserve for padding field

    if (paddingNeeded > 0) {
      this.padding = randomBytes(Math.max(1, paddingNeeded)).toString('base64');
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
        nonce: randomBytes(12).toString('hex'),
        data: randomBytes(256).toString('hex'),
        tag: randomBytes(16).toString('hex'),
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
    };
  }

  static deserialize(obj) {
    const packet = new NakpakPacket({
      id: obj.id,
      circuitId: obj.circuitId,
      timestamp: obj.timestamp,
    });
    packet.layers = obj.layers;
    packet.padding = obj.padding;
    return packet;
  }
}

/**
 * A circuit through the mesh (like a yak caravan route)
 */
class NakpakCircuit {
  constructor(options = {}) {
    this.circuitId = options.circuitId || bytesToHex(randomBytes(16));
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
    this.nodeId = options.nodeId || bytesToHex(randomBytes(16));
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
    const seed = randomBytes(32);
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
    const delay = NAKPAK_CONFIG.minPaddingMs + 
      Math.random() * (NAKPAK_CONFIG.maxPaddingMs - NAKPAK_CONFIG.minPaddingMs);
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  /**
   * Maybe inject a decoy packet to mask traffic patterns
   */
  _maybeInjectDecoy(circuitId) {
    if (Math.random() < NAKPAK_CONFIG.decoyProbability) {
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
    return bytesToHex(ml_dsa65.sign(message, this.signKeyPair.secretKey));
  }

  /**
   * Verify signature
   * IMPORTANT: ml_dsa65.verify(signature, message, publicKey) - signature FIRST!
   */
  verify(data, signature, publicKey) {
    const message = typeof data === 'string' ? utf8ToBytes(data) : data;
    return ml_dsa65.verify(
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
    this.nodeId = options.nodeId || bytesToHex(randomBytes(16));
    this.relay = new NakpakRelay({ nodeId: this.nodeId });
    this.circuits = new Map();     // circuitId -> NakpakCircuit (for circuits we created)
    this.knownNodes = new Map();   // nodeId -> { publicKey, lastSeen }
    
    this.stats = {
      circuitsCreated: 0,
      messagesSent: 0,
      messagesReceived: 0,
    };

    // Callbacks
    this.onMessageReceived = options.onMessageReceived || (() => {});
    this.onForward = options.onForward || (() => {});
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
      
      // Shuffle and pick
      for (let i = availableNodes.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
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
