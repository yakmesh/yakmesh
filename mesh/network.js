/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0. If a copy of that
 * license agreement was not distributed with this file, You can
 * find a link to the license at https://yakmesh.dev/license
 *
 * This Source Code Form is "Incompatible With Secondary Licenses",
 * as defined by the YAKMESH NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * ╔═══════════════════════════════════════════════════════════════════════════════╗
 * ║                    🌐 MANDALA NETWORK - SACRED GEOMETRY 🌐                    ║
 * ╠═══════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                               ║
 * ║  In Tibetan Buddhism, a MANDALA is a sacred geometric pattern representing   ║
 * ║  the cosmos—intricate, interconnected, and perfectly balanced. Each point    ║
 * ║  relates to every other, creating harmony through structure.                 ║
 * ║                                                                               ║
 * ║  The MANDALA Network embodies this principle:                                ║
 * ║  - Nodes form geometric patterns of connection                               ║
 * ║  - Messages flow through balanced pathways                                   ║
 * ║  - The whole emerges from the harmony of its parts                           ║
 * ║  - Each peer is essential to the cosmic structure                            ║
 * ║                                                                               ║
 * ║  PROTOCOL PHILOSOPHY:                                                         ║
 * ║    "Sacred geometry binds us" - Structure creates resilience                 ║
 * ║                                                                               ║
 * ║  SECURITY POLICY (2026-02-11):                                               ║
 * ║    ALL peer-to-peer communications MUST use ANNEX encryption.                ║
 * ║    - ML-KEM-768 key exchange on connection                                   ║
 * ║    - AES-256-GCM for message encryption                                      ║
 * ║    - No plaintext on wire between nodes                                      ║
 * ║                                                                               ║
 * ╚═══════════════════════════════════════════════════════════════════════════════╝
 * 
 * MANDALA Mesh Protocol
 * WebSocket-based peer-to-peer communication forming sacred network geometry
 * Encrypted via ANNEX (Autonomous Network Negotiated Encrypted eXchange)
 */

import { WebSocketServer, WebSocket } from 'ws';
import { networkInterfaces } from 'os';
import { ConnectionRateLimiter } from './rate-limiter.js';
import { createLogger } from '../utils/logger.js';

// ANNEX - Autonomous Network Negotiated Encrypted eXchange
// PQ-encrypted point-to-point communication between mesh peers
import { Annex, ChannelState } from './annex.js';

// JHILKE — Just Hidden In-band Legitimate Key Exchange (झिल्के — cricket chirps)
// Deterministic bootstrap + steganographic rekey coordination
import { JhilkeCoordinator } from './jhilke.js';

// MessageValidator + SafeJsonParser — size limits, depth checks, proto pollution guard
import MessageValidator, { SafeJsonParser } from './message-validator.js';

// Hardware capabilities for HELLO/WELCOME peer exchange
import { getCapabilities } from '../utils/accel.js';

// PRAHARI — sponge-based entropy for all randomness
import { seedStore } from '../security/prahari.js';

// AGUWA — Kuramoto time backbone, peer phase tracking
import { aguwa } from './aguwa.js';

// TRIBHUJ Key Ratchet — trinary rotating keypairs with gateway attestation
import { TribhujRatchet, GatewayAttestation } from '../identity/tribhuj-ratchet.js';
import { generateNodeId, signatureToWire } from '../identity/node-key.js';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';

/** Extract unique peer suffix from nodeId (e.g. 'node-net-name-pq-kEEU' → 'kEEU') */
const peerTag = (id) => id?.split('-pq-').pop() || id?.slice?.(-8) || String(id);

const log = createLogger('mandala:network');

/**
 * Message types for MANDALA mesh protocol
 * Each message type represents a sacred communication form
 */
export const MandalaMessageTypes = {
  // Handshake (greeting rituals)
  HELLO: 'hello',           // Initial connection with identity
  WELCOME: 'welcome',       // Response to hello

  // Node management (maintaining the mandala pattern)
  PING: 'ping',
  PONG: 'pong',
  PEERS: 'peers',           // Share known peers (reveal the pattern)

  // Data replication (sacred knowledge transmission)
  SYNC_REQUEST: 'sync_request',
  SYNC_RESPONSE: 'sync_response',
  REPLICATE: 'replicate',   // Push new data

  // Gossip (whispered teachings)
  GOSSIP: 'gossip',         // Broadcast message

  // TME — Temporal Mesh Encoding wire protocol (Step 23)
  TME_SLICE: 'tme_slice',               // Push a temporal slice to a peer
  TME_PROOF_REQUEST: 'tme_proof_request', // Request a timing proof for a slice
  TME_PROOF_RESPONSE: 'tme_proof_response', // Return a timing proof
  TME_RECONSTRUCT: 'tme_reconstruct',   // Request full reconstruction of a stream

  // Admission (capacity management)
  REDIRECT: 'redirect',     // Forward peer to another node with capacity
  HOLD: 'hold',           // SAMUHA — peer queued pending a free slot
};

// Backward compatibility alias
export const MessageTypes = MandalaMessageTypes;

// Handshake/control types always ride plaintext: they are proof-of-
// possession signed and MUST reach the handshake handler on the actual
// socket they arrived on. ANNEX-wrapping them re-dispatches the decrypted
// payload against the peer's REGISTERED socket — the HELLO handler then
// re-registers the peer on its existing wire (dual-wire churn) and the
// WELCOME reply goes to the wrong socket (dial times out, promotion never
// completes).
export const HANDSHAKE_PLAINTEXT_TYPES = new Set([
  MandalaMessageTypes.HELLO,
  MandalaMessageTypes.WELCOME,
  MandalaMessageTypes.REDIRECT,
  MandalaMessageTypes.HOLD,
  'REJECT',
]);

/**
 * MANDALA Network Manager
 * Handles peer connections and message routing through sacred geometry
 */
export class MandalaNetwork {
  constructor(identity, config = {}) {
    this.identity = identity;
    this.config = {
      wsPort: config.wsPort || 9001,
      pingInterval: config.pingInterval || 30000,
      portRetries: config.portRetries || 10,  // Try up to 10 sequential ports
      // Max peers allowed in HELLO/WELCOME handshake simultaneously.
      // Total connected peers is UNBOUNDED — the mesh scales freely.
      // This only gates the handshake window to prevent Sybil flood attacks.
      maxConcurrentHandshakes: config.maxConcurrentHandshakes || 50,
      // SAMUHA HOLD queue — peers in the ABSTAIN utilization band wait for
      // a slot instead of being rejected. Spec: 30s timeout, depth 10,
      // overflow and timeout both degrade to REDIRECT.
      holdTimeoutMs: config.holdTimeoutMs || 30000,
      holdQueueMax: config.holdQueueMax || 10,
      ...config,
    };

    // Track actual bound port (may differ from config if fallback used)
    this.boundPort = null;

    // Network identity for code proof verification
    this.networkId = config.networkId || null;
    this.networkFingerprint = config.networkFingerprint || null;

    // Oracle code hash for JHILKE bootstrap key derivation
    this.codeHash = config.codeHash || null;

    // Build nonce for JHILKE bootstrap key + dialect strengthening
    this.buildNonce = config.buildNonce || null;

    this.server = null;
    this.peers = new Map();        // nodeId -> { ws, identity, lastSeen }
    this.knownNodes = new Map();   // nodeId -> { endpoint, identity }
    this.messageHandlers = new Map();
    this.seenMessages = new Set(); // For gossip deduplication

    // ANNEX - PQ-encrypted point-to-point channels
    // Initialized after start() when identity is available
    this.annex = null;

    // TRIBHUJ ratchet - trinary rotating keypairs for forward secrecy
    this.ratchet = null;
    this.gateway = null;  // Gateway attestation for gossip verify-once

    // Track peer ratchet states (their announced TRIBHUJ public keys)
    this.peerRatchets = new Map(); // nodeId -> { currentPubKey, previousPubKey, epoch }

    // Rate limiter for connection/message flood protection
    this.rateLimiter = new ConnectionRateLimiter(config.rateLimiter || {});

    // Concurrent handshake tracking — limits how many peers can be in the
    // HELLO/WELCOME negotiation window at the same time. Legitimate nodes
    // trickle in; a burst of 200 simultaneous connections is a Sybil tell.
    // Total peer count is UNBOUNDED (mesh scales freely).
    this._pendingHandshakeCount = 0;
    this._pendingHandshakeWs = new Set();  // Track WSs in handshake state

    // SAMUHA HOLD queue — { ws, nodeId, msg, req, priority, enqueuedAt, timer }
    this._holdQueue = [];

    // Connection burst detector — sliding window for GPS-timestamped alerts.
    // A sudden spike from baseline to hundreds of connections per minute
    // shows up as a "bright spot" with microsecond-precise timing evidence.
    this._burstWindow = [];           // [{ ts, ip }] — last 60s of connections
    this._burstWindowMs = 60000;      // 60-second sliding window
    this._burstThreshold = 30;        // connections/minute that trigger alert
    this._burstAlerted = false;       // debounce: one alert per burst episode
    this._burstAlertTimeout = null;   // stored handle for cleanup

    // KARMA trust model reference — set via setKarmaModel() from server/index.js
    this._karmaModel = null;
    this._burstStats = {
      totalBurstsDetected: 0,
      lastBurstAt: null,
      lastBurstRate: 0,
      peakRate: 0,
    };

    // Message validation — size limits, depth limits, proto pollution guard
    // This was implemented but never wired in. Now it gates ALL incoming WS messages.
    this.messageValidator = new MessageValidator();
    this.safeJsonParser = new SafeJsonParser();

    this._setupDefaultHandlers();
  }

  /**
   * Start the WebSocket server with automatic port fallback
   */
  async start() {
    const basePort = this.config.wsPort;
    const maxRetries = this.config.portRetries;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const port = basePort + attempt;
      try {
        await this._tryBindPort(port);
        this.boundPort = port;
        if (attempt > 0) {
          log.warn('Port was in use, bound to alternate', { originalPort: basePort, boundPort: port });
        }
        log.info('Mesh server listening', { url: `ws://localhost:${port}` });

        // Initialize ANNEX encryption layer
        this.annex = new Annex({ identity: this.identity, mesh: this });

        // CRITICAL: Route decrypted ANNEX payloads back to mesh handlers.
        // Without this, messages encrypted by _send() via ANNEX are decrypted
        // but never dispatched to GOSSIP/PING/PONG handlers — they vanish.
        this.annex.onMessage(async (msg) => {
          const payload = msg.payload;
          if (!payload || typeof payload !== 'object') return;

          const msgType = payload.type || 'gossip';
          // Handshake types never legitimately arrive via ANNEX — _send
          // keeps them plaintext. Dropping here prevents a decrypted HELLO
          // from re-running registration against the primary socket.
          if (HANDSHAKE_PLAINTEXT_TYPES.has(msgType)) return;
          const handlers = this.messageHandlers.get(msgType) || [];
          if (handlers.length === 0) return;

          // Find the WS for this peer (needed by PING handler etc.)
          const peer = this.peers.get(msg.from);
          if (!peer) return;  // No peer = stale ANNEX session, skip

          for (const handler of handlers) {
            try {
              handler(payload, peer.ws, msg.from);
            } catch (err) {
              log.warn('ANNEX→mesh handler error', { type: msgType, error: err.message });
            }
          }
        });
        log.info('ANNEX encryption layer initialized');

        // Initialize JHILKE coordinator (bootstrap + friend-or-foe verification)
        if (this.codeHash) {
          this.jhilke = new JhilkeCoordinator({
            codeHash: this.codeHash,
            nodeId: this.identity.identity.nodeId,
            mesh: this,
            buildNonce: this.buildNonce,
          });
          this.jhilke.start();  // Start 30s friend-or-foe chirp loop
          log.info('JHILKE coordinator initialized (cricket chorus active)');
        }

        // Initialize TRIBHUJ key ratchet — trinary rotating keypairs
        this.ratchet = new TribhujRatchet({
          rotationInterval: this.config.tribhujRotation || 300000,  // 5min default
          gracePeriod: this.config.tribhujGrace || 60000,           // 1min grace
        });
        await this.ratchet.initialize();
        this.ratchet.startAutoRotation();

        // Gateway attestation — verify gossip once, attest for downstream
        this.gateway = new GatewayAttestation(
          this.identity.identity.nodeId,
          this.ratchet,
          { attestationTTL: 60000 }
        );
        log.info('TRIBHUJ ratchet + gateway attestation initialized');

        this._startPingLoop();
        return;
      } catch (err) {
        if (err.code === 'EADDRINUSE' && attempt < maxRetries - 1) {
          continue; // Try next port
        }
        throw err;
      }
    }

    throw new Error(`Could not bind to any port in range ${basePort}-${basePort + maxRetries - 1}`);
  }

  /**
   * Attempt to bind to a specific port
   */
  _tryBindPort(port) {
    return new Promise((resolve, reject) => {
      const server = new WebSocketServer({ port, maxPayload: 1048576 }); // 1MB max message size

      server.on('listening', () => {
        this.server = server;

        server.on('connection', (ws, req) => {
          this._handleIncomingConnection(ws, req);
        });

        server.on('error', (err) => {
          console.error('Mesh server error:', err);
        });

        resolve();
      });

      server.on('error', (err) => {
        reject(err);
      });
    });
  }

  /**
   * Connect to a peer node. When the target nodeId is known and YAK-TUN's
   * UDP underlay (wire B) is proven up for it, the overlay endpoint
   * (ws://<vIP>:wsPort) is attempted first — session traffic then rides
   * inside the tunnel. Falls back to the given real endpoint on failure.
   * @param {string} endpoint - WebSocket URL (real/underlay endpoint)
   * @param {string|null} targetNodeId - Expected nodeId (from gossip/SHERPA).
   *   When provided, WELCOME handler verifies the responding nodeId matches,
   *   preventing MITM substitution attacks.
   */
  async connect(endpoint, targetNodeId = null, opts = {}) {
    // Self-dial guard — a node never connects to itself. Auto-dial paths
    // (gossip echo of our own record, stale learned endpoints, bootstrap
    // self-skip misses on NAT'd hosts) can all present our own nodeId.
    if (targetNodeId && targetNodeId === this.identity?.identity?.nodeId) {
      throw new Error(`refusing self-dial to ${String(targetNodeId).slice(0, 24)}`);
    }

    // In-flight dedup — concurrent dials to the same peer (discovery +
    // peer-registered + reconnect racing) must not each open a socket;
    // they trip the remote's connection-flood limiter and waste a ban.
    this._inflightDials ||= new Set();
    const dialKey = targetNodeId || endpoint;
    if (this._inflightDials.has(dialKey)) {
      throw new Error(`dial already in flight for ${String(dialKey).slice(0, 24)}`);
    }
    this._inflightDials.add(dialKey);
    try {
      // Tunnel-first dialing: only for already-registered peers (a first-
      // contact dial should hit the real endpoint so the LAN lifeline
      // exists before the overlay promotes). Requires proven wire B —
      // the SYN has to reach the peer as a UDP datagram.
      if (!opts.direct && targetNodeId && this.peers.has(targetNodeId)
          && this.yakTun?.overlayEndpointFor) {
        const hostMatch = endpoint.match(/^wss?:\/\/\[?([^\]:\/]+)/);
        const isTunTarget = hostMatch && MandalaNetwork._isTunnelIp(hostMatch[1]);
        if (!isTunTarget) {
          const overlay = this.yakTun.overlayEndpointFor(targetNodeId);
          if (overlay && overlay !== endpoint) {
            try {
              return await this._connectOnce(overlay, targetNodeId, { handshakeMs: 8000 });
            } catch (err) {
              log.debug('Overlay dial failed — falling back to real endpoint', {
                peer: peerTag(targetNodeId), overlay, error: err.message,
              });
            }
          }
        }
      }
      return await this._connectOnce(endpoint, targetNodeId);
    } finally {
      this._inflightDials.delete(dialKey);
    }
  }

  /**
   * Single dial attempt. Split from connect() so the tunnel-preferred
   * overlay attempt can fall back to the real endpoint cleanly.
   */
  async _connectOnce(endpoint, targetNodeId = null, opts = {}) {
    return new Promise((resolve, reject) => {
      log.debug('Connecting to peer', { endpoint, targetNodeId: targetNodeId ? peerTag(targetNodeId) : null });
      let settled = false;
      const handshakeMs = opts.handshakeMs || 15000;

      const ws = new WebSocket(endpoint);
      ws._outboundEndpoint = endpoint;  // Track origin for reconnect detection
      const hostMatch = endpoint.match(/^wss?:\/\/\[?([^\]:\/]+)/);
      if (hostMatch && MandalaNetwork._isTunnelIp(hostMatch[1])) ws._viaTun = true;
      if (targetNodeId) ws._targetNodeId = targetNodeId;

      ws.on('open', () => {
        // Send HELLO with our identity AND network fingerprint for code proof verification
        // Include our advertised endpoint so inbound peers know how to reach us
        // Include proof-of-possession: sign "YAKMESH:HELLO:{nodeId}:{timestamp}:{tribhujPubKey}"
        // The ratchet pubkey is bound INSIDE the proof so it can't be swapped in transit.
        const timestamp = Date.now();
        const nodeId = this.identity.identity.nodeId;
        const tribhujPubKey = this.ratchet?._current?.publicKey
          ? bytesToHex(this.ratchet._current.publicKey) : null;
        const tribhujPrevPubKey = this.ratchet?._previous?.publicKey
          ? bytesToHex(this.ratchet._previous.publicKey) : null;
        const proofPayload = `YAKMESH:HELLO:${nodeId}:${timestamp}:${tribhujPubKey || ''}`;
        if (!this._announcedRatchetKeys) this._announcedRatchetKeys = new Set();
        if (tribhujPubKey) this._announcedRatchetKeys.add(tribhujPubKey);
        if (tribhujPrevPubKey) this._announcedRatchetKeys.add(tribhujPrevPubKey);
        this._send(ws, {
          type: MessageTypes.HELLO,
          identity: {
            ...this.identity.getPublicIdentity(),
            tribhujPubKey,
            tribhujPrevPubKey,
            networkId: this.networkId,
            networkFingerprint: this.networkFingerprint,
          },
          advertisedEndpoint: this._getAdvertisedEndpoint(),
          capabilities: getCapabilities(),
          timestamp,
          proof: this.identity.sign(proofPayload),
          // SAMUHA referral — if a peer redirected us here, present the
          // signed token they issued so the target can verify the handoff.
          ...(this._pendingReferral && this._pendingReferral.exp > Date.now()
            ? { referral: this._pendingReferral }
            : {}),
        });
      });

      ws.on('message', (data) => {
        this._handleMessage(ws, data, null);
      });

      ws.on('close', () => {
        // A socket that closes before WELCOME (duplicate-connection
        // rejection, remote restart, dead listener) fails the connect
        // immediately rather than waiting out the handshake timeout.
        if (!settled) {
          settled = true;
          clearTimeout(handshakeTimeout);
          reject(new Error(`Connection closed before WELCOME from ${endpoint}`));
        }
        this._handleDisconnect(ws);
      });

      ws.on('error', (err) => {
        if (!settled) {
          settled = true;
          clearTimeout(handshakeTimeout);
          log.debug(`Connection to ${endpoint} failed: ${err.message}`);
          reject(err);
        }
        // If already settled (e.g. caller timed out), just silently close
        try { ws.close(); } catch { }
      });

      // Handshake timeout — a socket that opens but never completes the
      // WELCOME exchange (silent firewall, duplicate-close, dead listener)
      // must fail rather than hold the caller's promise forever.
      const handshakeTimeout = setTimeout(() => {
        if (!settled) {
          settled = true;
          try { ws.close(); } catch { }
          reject(new Error(`Handshake timeout — no WELCOME from ${endpoint}`));
        }
      }, handshakeMs);

      // Resolve when we get WELCOME back
      const welcomeHandler = (msg) => {
        if (msg.type === MessageTypes.WELCOME && !settled) {
          settled = true;
          clearTimeout(handshakeTimeout);
          log.info('Connected to peer', { nodeId: msg.identity.nodeId });
          resolve(msg.identity);
        }
      };
      ws._pendingWelcome = welcomeHandler;
    });
  }

  /**
   * Send encrypted message to specific peer via ANNEX.
   * HARD FAIL: If no ANNEX session exists, the message is NOT sent.
   * Caller must handle the error and initiate ANNEX negotiation.
   */
  async sendEncrypted(nodeId, payload) {
    if (this.annex) {
      const session = this.annex.sessions.get(nodeId);
      if (session?.established && !session.isExpired()) {
        return await this.annex.send(nodeId, payload);
      }
    }
    // HARD FAIL: No plaintext fallback. Encryption is mandatory.
    const err = new Error(`No active ANNEX session for ${peerTag(nodeId)} — refusing plaintext send`);
    log.error(err.message);
    throw err;
  }

  /**
   * Get ANNEX encryption stats
   */
  getAnnexStats() {
    return this.annex?.getStats() || { activeSessions: 0, note: 'ANNEX not initialized' };
  }

  /**
   * Broadcast message to all peers (gossip)
   */
  broadcast(message) {
    const msgId = `${this.identity.identity.nodeId}-${Date.now()}-${seedStore.squeeze(8, 'MANDALA-MSG-ID').toString('hex')}`;

    const gossipMsg = {
      type: MessageTypes.GOSSIP,
      id: msgId,
      origin: this.identity.identity.nodeId,
      payload: message,
      ttl: 10,
      timestamp: Date.now(),
    };

    // Sign the message — prefer TRIBHUJ ratchet for forward secrecy, fall back
    // to identity. Broadcast payloads are app-level (seva, beacon, …) where
    // this signature is the only hop authentication, so it stays.
    const signed = this.ratchet
      ? this.ratchet.signObject(gossipMsg)
      : this.identity.signObject(gossipMsg);

    this.seenMessages.add(msgId);

    // Send to all WS peers — peers whose pinned ratchet key is stale get the
    // rotation certificate attached so they can certify the new key.
    for (const [nodeId, peer] of this.peers) {
      this._send(peer.ws, this._attachTribhujCert(signed, peer));
    }

    // Emit for HTTP relay peers (server layer hooks this) — relay peers are
    // anonymous to us, so the emitted copy always carries the cert.
    this.emit('outbound-gossip', this._attachTribhujCert(signed, null), []);
  }

  /**
   * Send message to specific peer (WS or relay fallback)
   */
  sendTo(nodeId, message) {
    const outbound = { ...message, timestamp: Date.now() };
    // Rumor-carrying gossip wrappers carry their own end-to-end authentication
    // (rumor.signature or data.signature for self-signed payloads), and the
    // ANNEX session already authenticates the sending hop — a third signature
    // here is pure redundancy (~10.5KB hex + cert machinery per message).
    // Other message types keep ratchet/identity signing as their hop auth.
    const isRumorWrapper = outbound.type === MessageTypes.GOSSIP &&
      outbound.payload?.gossip?.type === 'GOSSIP_RUMOR';
    const signed = isRumorWrapper
      ? outbound
      : this.ratchet
        ? this.ratchet.signObject(outbound)
        : this.identity.signObject(outbound);

    const peer = this.peers.get(nodeId);
    if (peer) {
      // Wire policy: TUN_PACKET is the tunnel's own carrier — it must use
      // the LAN wire. Sending it on the overlay would recurse (the write
      // generates TCP-to-vIP → tun capture → sendTo → same socket).
      // Everything else rides the primary socket, which is the overlay
      // whenever wire B is up.
      let sock = peer.ws;
      if (outbound.type === 'TUN_PACKET' && peer.wsVia === 'tun') {
        sock = peer.lifelineWs;
      }
      if (sock && sock.readyState === WebSocket.OPEN) {
        this._send(sock, signed._tribhujSig ? this._attachTribhujCert(signed, peer) : signed);
        return;
      }
    }

    // Not a WS peer — try relay fallback (server layer hooks this). The peer's
    // pinned state is unknown, so the relayed copy carries the cert.
    this.emit('outbound-relay', nodeId, this._attachTribhujCert(signed, null));
  }

  /**
   * Attach a TRIBHUJ rotation certificate to a ratchet-signed message while
   * the current ratchet key is inside its announce window. The cert is a
   * signature by our permanent identity key over
   * "YAKMESH:TRIBHUJ-KEY:{nodeId}:{newKey}:{epoch}" — receivers verify it
   * against the pinned identity key and advance their pinned ratchet set.
   *
   * Announce window: peers pin current+previous at handshake, so only peers
   * connected BEFORE a rotation can be stale. The previous design attached
   * the cert to a single message after rotation — any peer that missed it
   * could never certify the key and rejected all signed traffic until the
   * next rotation. Attaching for a window after each rotation guarantees
   * every connected peer sees it many times. The cert signature is computed
   * once per key and cached.
   */
  _attachTribhujCert(signed, peer = null) {
    const cur = this.ratchet?._current?.publicKey;
    if (!cur || signed._tribhujCert) return signed;
    const epoch = this.ratchet._epoch;
    const now = Date.now();
    if (this._ratchetEpochSeen === undefined) {
      // First observation — genesis keys are pinned via handshake, not a rotation.
      this._ratchetEpochSeen = epoch;
      this._ratchetEpochAnnouncedAt = 0;
    } else if (this._ratchetEpochSeen !== epoch) {
      this._ratchetEpochSeen = epoch;
      this._ratchetEpochAnnouncedAt = now;
    }
    if (now - this._ratchetEpochAnnouncedAt > 90_000) return signed;
    const curHex = bytesToHex(cur);
    if (!this._ratchetKeyCerts) this._ratchetKeyCerts = new Map();
    let cert = this._ratchetKeyCerts.get(curHex);
    if (!cert) {
      const certPayload = `YAKMESH:TRIBHUJ-KEY:${this.identity.identity.nodeId}:${curHex}:${epoch}`;
      cert = signatureToWire(this.identity.sign(certPayload));
      this._ratchetKeyCerts.set(curHex, cert);
      if (this._ratchetKeyCerts.size > 8) {
        const oldest = this._ratchetKeyCerts.keys().next().value;
        this._ratchetKeyCerts.delete(oldest);
      }
    }
    signed._tribhujCert = cert;
    return signed;
  }

  /**
   * Register a message handler
   */
  on(messageType, handler) {
    if (!this.messageHandlers.has(messageType)) {
      this.messageHandlers.set(messageType, []);
    }
    this.messageHandlers.get(messageType).push(handler);
  }

  /**
   * Remove a message handler
   */
  off(messageType, handler) {
    if (!this.messageHandlers.has(messageType)) return;
    const handlers = this.messageHandlers.get(messageType);
    const idx = handlers.indexOf(handler);
    if (idx >= 0) handlers.splice(idx, 1);
  }

  /**
   * Emit an event to handlers
   */
  emit(eventType, ...args) {
    const handlers = this.messageHandlers.get(eventType) || [];
    for (const handler of handlers) {
      handler(...args);
    }
  }

  /**
   * Check if connected to a specific node
   */
  isConnectedTo(nodeId) {
    return this.peers.has(nodeId);
  }

  /**
   * Connect to a peer (alias for connect)
   */
  async connectToPeer(endpoint, targetNodeId = null) {
    return this.connect(endpoint, targetNodeId);
  }

  /**
   * Get public endpoint for this node
   */
  getPublicEndpoint() {
    if (this.config.publicHost) {
      return `ws://${this.config.publicHost}:${this.config.wsPort}`;
    }
    return null;
  }

  /**
   * Get list of connected peers
   */
  getPeers() {
    return Array.from(this.peers.entries()).map(([nodeId, peer]) => ({
      nodeId,
      name: peer.identity.name,
      endpoint: peer.endpoint,
      lastSeen: peer.lastSeen,
      connectedAt: peer.connectedAt || null,
      via: peer.wsVia || 'lan',
      lifeline: !!peer.lifelineWs,
      // SAMUHA admission record — verdict (+1 admit / 0 hold / -1 redirect)
      // and composite priority at accept time
      admission: peer.admission || null,
    }));
  }

  /**
   * SAMUHA admission-control status — AGUWA's utilization/verdict tally
   * merged with the live HOLD-queue state for the /api/samuha surface.
   */
  getSamuhaStatus() {
    return {
      ...aguwa.admissionStatus(),
      holdQueue: {
        depth: this._holdQueue.length,
        maxDepth: this.config.holdQueueMax,
        timeoutMs: this.config.holdTimeoutMs,
        waiting: this._holdQueue.map(e => ({
          nodeId: e.nodeId,
          priority: +e.priority.toFixed(4),
          waitedMs: Date.now() - e.enqueuedAt,
        })),
      },
    };
  }

  /**
   * Is this address inside the YAK-TUN virtual subnet? Covers v4
   * (10.199.0.0/16, incl. IPv4-mapped IPv6) and the ULA fd99:199::/48.
   * Tunnel IPs are identity-derived overlays — they are NOT dialable
   * endpoints for peers that lack a route to us through the tunnel.
   */
  static _isTunnelIp(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const a = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
    return a.startsWith('10.199.') || a.toLowerCase().startsWith('fd99:199:');
  }

  /**
   * Loopback/unspecified hosts in an endpoint are only meaningful to the
   * advertiser itself — a remote peer dialing 127.x reaches its OWN
   * listener, not the advertiser. Learned endpoints (gossip, referrals,
   * discovery, advertisedEndpoint) must never be dialed when loopback.
   * Configured paths (YAKMESH_BOOTSTRAP seeds, explicit /connect) bypass
   * this check — an operator may legitimately point at a local forward.
   */
  static _isLoopbackHost(host) {
    if (!host || typeof host !== 'string') return false;
    const h = host.startsWith('::ffff:') ? host.slice(7) : host;
    return h === '::1' || h === 'localhost' || h === '0.0.0.0' || h.startsWith('127.');
  }

  /** Extract the host from a ws:// endpoint (bracketed IPv6 aware), or null. */
  static _endpointHost(endpoint) {
    const m = (endpoint || '').match(/^wss?:\/\/(\[[^\]]+\]|[^:\/]+)/);
    if (!m) return null;
    return m[1].startsWith('[') ? m[1].slice(1, -1) : m[1];
  }

  /**
   * Get our advertised WebSocket endpoint for peer discovery.
   * This tells inbound peers how to reconnect to us.
   */
  _getAdvertisedEndpoint() {
    if (!this.boundPort) return null;

    // Use configured advertise address if set (for NAT/proxy scenarios)
    if (this.config.advertiseAddress) {
      return this.config.advertiseAddress;
    }

    // Otherwise construct from best-guess local IP + bound port
    // Prefer non-localhost addresses for LAN/WAN connectivity
    const ifaces = networkInterfaces();
    let bestIp = '127.0.0.1';

    for (const [name, addrs] of Object.entries(ifaces)) {
      for (const addr of addrs) {
        if (addr.family === 'IPv4' && !addr.internal) {
          // YAK-TUN vIPs are never advertised — a peer without an underlay
          // route could never dial them, and enumeration order is not
          // guaranteed to prefer the physical NIC.
          if (MandalaNetwork._isTunnelIp(addr.address)) continue;
          // Prefer 192.168.x.x or 10.x.x.x (private networks)
          if (addr.address.startsWith('192.168.') || addr.address.startsWith('10.')) {
            bestIp = addr.address;
            break;
          }
          // Fallback to any non-internal IPv4
          if (bestIp === '127.0.0.1') {
            bestIp = addr.address;
          }
        }
      }
    }

    // No remotely-usable address → advertise nothing. A loopback endpoint
    // propagated through gossip makes remote peers dial their own listener
    // (observed live: an outbound-only container advertised
    // ws://127.0.0.1:9080 and kept dialing itself via the echoed record).
    if (bestIp === '127.0.0.1') return null;

    return `ws://${bestIp}:${this.boundPort}`;
  }

  /**
   * Stop the mesh server
   */
  async stop() {
    // Stop ping loop
    if (this._pingInterval) {
      clearInterval(this._pingInterval);
      this._pingInterval = null;
    }
    clearTimeout(this._burstAlertTimeout);

    // Close all ANNEX channels
    if (this.annex) {
      for (const nodeId of this.annex.sessions.keys()) {
        try { await this.annex.closeChannel(nodeId); } catch { }
      }
      this.annex = null;
    }

    // Stop JHILKE coordinator
    if (this.jhilke) {
      this.jhilke.stop();
      this.jhilke = null;
    }

    // Destroy TRIBHUJ ratchet — zero all key material
    if (this.ratchet) {
      this.ratchet.destroy();
      this.ratchet = null;
    }
    this.gateway = null;
    this.peerRatchets.clear();

    // Close all peer connections — both wires
    for (const [nodeId, peer] of this.peers) {
      try { peer.ws.close(); } catch { }
      try { peer.lifelineWs?.close(); } catch { }
    }
    this.peers.clear();

    // Stop server
    if (this.server) {
      this.server.close();
      this.server = null;
    }

    log.info('Mesh server stopped');
  }

  /** Set KARMA trust model reference for admission decisions */
  setKarmaModel(model) { this._karmaModel = model; }

  // ===== Private Methods =====

  _setupDefaultHandlers() {
    // Handle HELLO
    this.on(MessageTypes.HELLO, (msg, ws) => {
      const nodeId = msg.identity.nodeId;

      // CODE PROOF VERIFICATION: Check network fingerprint
      // Nodes with different codebases will have different fingerprints
      if (this.networkFingerprint && msg.identity.networkFingerprint) {
        if (msg.identity.networkFingerprint !== this.networkFingerprint) {
          console.warn(`✗ Rejected peer ${peerTag(nodeId)} - incompatible codebase`);
          console.warn(`  Their network: ${msg.identity.networkId || 'unknown'}`);
          console.warn(`  Our network:   ${this.networkId || 'unknown'}`);

          // Send rejection and close connection
          this._send(ws, {
            type: 'REJECT',
            reason: 'INCOMPATIBLE_CODEBASE',
            message: 'Your node is running a different codebase version',
            ourNetworkId: this.networkId,
          });
          ws.close(1008, 'Incompatible codebase');
          return;
        }
      }

      // REPLAY PROTECTION: timestamp must be within a 5-minute window
      if (!msg.timestamp || Math.abs(Date.now() - msg.timestamp) > 5 * 60 * 1000) {
        log.warn('Rejected HELLO — stale or missing timestamp', { peer: peerTag(nodeId) });
        ws.close(1008, 'Stale handshake timestamp');
        return;
      }

      // PROOF OF POSSESSION: Verify the sender controls the claimed private key.
      // The HELLO must include a signature of
      // "YAKMESH:HELLO:{nodeId}:{timestamp}:{tribhujPubKey}" under the claimed
      // publicKey. The ratchet key is bound inside the proof so it can't be
      // swapped by a relay.
      const claimedPubKey = msg.identity?.publicKey;
      const claimedTribhuj = msg.identity?.tribhujPubKey || '';
      const proofPayload = `YAKMESH:HELLO:${nodeId}:${msg.timestamp}:${claimedTribhuj}`;
      if (!claimedPubKey || !msg.proof || !this.identity.verify(proofPayload, msg.proof, claimedPubKey)) {
        log.warn('Rejected HELLO — invalid proof of possession', {
          peer: peerTag(nodeId),
          hasPubKey: !!claimedPubKey,
          hasProof: !!msg.proof,
        });
        this._send(ws, {
          type: 'REJECT',
          reason: 'PROOF_OF_POSSESSION_FAILED',
          message: 'HELLO must include a valid proof signature',
        });
        ws.close(1008, 'Proof of possession failed');
        return;
      }

      // IDENTITY BINDING: nodeId must be derived from the claimed publicKey.
      // Otherwise an attacker could claim a victim's nodeId while presenting
      // their own publicKey + a valid signature under their own key.
      try {
        const derivedNodeId = generateNodeId(hexToBytes(claimedPubKey));
        if (derivedNodeId !== nodeId) {
          log.warn('Rejected HELLO — nodeId not bound to publicKey', {
            claimed: peerTag(nodeId),
            derived: peerTag(derivedNodeId),
          });
          this._send(ws, {
            type: 'REJECT',
            reason: 'IDENTITY_BINDING_FAILED',
            message: 'nodeId does not match the claimed public key',
          });
          ws.close(1008, 'Identity binding failed');
          return;
        }
      } catch (err) {
        log.warn('Rejected HELLO — could not verify identity binding', { error: err.message });
        ws.close(1008, 'Identity binding failed');
        return;
      }

      // SELF-CONNECTION REJECT: a HELLO carrying our own nodeId can only
      // come from ourselves (loopback dial, NAT hairpin, echoed endpoint).
      // A node must never register itself as a peer — drop the socket.
      if (nodeId === this.identity?.identity?.nodeId) {
        log.warn('Rejected HELLO — self-connection (own nodeId)', { ip: ws._clientIp });
        try { ws.close(1008, 'Self-connection'); } catch { }
        return;
      }

      // DUPLICATE / RECONNECT DETECTION: If this peer is already connected
      // with a different WebSocket, decide which connection to keep.
      const existingPeer = this.peers.get(nodeId);
      log.info('HELLO handshake', {
        peer: peerTag(nodeId), ip: ws._clientIp, viaTun: !!ws._viaTun,
        known: !!existingPeer,
        existingAlive: existingPeer ? existingPeer.ws.readyState === WebSocket.OPEN : null,
      });
      if (existingPeer && existingPeer.ws !== ws) {
        const oldAlive = existingPeer.ws.readyState === WebSocket.OPEN;
        if (oldAlive) {
          // Dual-wire: a socket on the OTHER wire is a second link, not a
          // duplicate. Identity is already verified above (PoP + binding),
          // so attach, answer WELCOME, and skip re-registration.
          if (this._attachSecondWire(existingPeer, ws, nodeId)) {
            if (this._pendingHandshakeWs.has(ws)) {
              this._pendingHandshakeCount = Math.max(0, this._pendingHandshakeCount - 1);
              this._pendingHandshakeWs.delete(ws);
            }
            this._sendWelcome(ws, nodeId);
            return;
          }
          // Existing connection is still alive — this is a duplicate, not a
          // reconnect. Close the NEW socket to avoid ping-pong overwrites.
          log.info('Duplicate connection from peer — keeping existing WS', { peer: peerTag(nodeId) });
          try { ws.close(1000, 'Duplicate connection'); } catch { }
          return;
        }
        // Old WS is dead — genuine reconnect. Reset ANNEX state.
        log.info('Peer reconnected (new WS) — resetting ANNEX/JHILKE state', { peer: peerTag(nodeId) });
        if (this.annex) {
          this.annex.sessions.delete(nodeId);
          this.annex.pendingHandshakes.delete(nodeId);
        }
        if (this.jhilke) {
          this.jhilke.cleanupPeer(nodeId);
        }
        try { existingPeer.ws.close(1000, 'Replaced by reconnect'); } catch { }
      }

      // SAMUHA referral check — a REDIRECTed peer may present the signed
      // referral token we issue. Valid iff: unexpired, referrer is a node
      // we actually know, and the signature verifies under their key.
      // Prevents open-season abuse of the redirect mechanism; logged as
      // evidence either way.
      if (msg.referral && typeof msg.referral === 'object') {
        const { by, exp, sig } = msg.referral;
        const referrer = this.peers.get(by) || this.knownNodes.get(by);
        const referrerPk = referrer?.identity?.publicKey;
        if (by && exp && sig && Date.now() < exp && referrerPk &&
            this.identity.verify(`YAKMESH:REFERRAL:${nodeId}:${exp}`, sig, referrerPk)) {
          ws._referralVerified = true;
          log.info('SAMUHA referral verified', { peer: peerTag(nodeId), referrer: peerTag(by) });
        } else if (by || sig) {
          log.debug('SAMUHA referral rejected (unknown referrer, expired, or bad sig)', {
            peer: peerTag(nodeId), referrer: by ? peerTag(by) : 'none',
          });
        }
      }

      // ── Weighted Ternary Admission (Phase 3) ──
      // Check capacity BEFORE storing peer. HELLO already carries capabilities
      // and persistentId — we use these + persisted KARMA to decide.
      const admission = aguwa.admissionVerdict({
        capabilities: msg.capabilities,
        persistentId: msg.identity?.persistentId,
        karmaModel: this._karmaModel || null,
      });

      if (admission.verdict === -1 && admission.lowestPeer) {
        // Incoming beats lowest connected → evict lowest via REDIRECT
        const lowestWs = this.peers.get(admission.lowestPeer)?.ws;
        if (lowestWs && lowestWs.readyState === WebSocket.OPEN) {
          const forwardEndpoint = msg.advertisedEndpoint || null;
          const evictExp = Date.now() + 60000;
          this._send(lowestWs, {
            type: MessageTypes.REDIRECT,
            endpoint: forwardEndpoint,
            reason: 'capacity_eviction',
            // Referral bound to the EVICTED peer — it presents this when
            // connecting to the incoming peer that displaced it.
            referral: this.identity?.sign ? {
              by: this.identity.identity.nodeId,
              exp: evictExp,
              sig: this.identity.sign(`YAKMESH:REFERRAL:${admission.lowestPeer}:${evictExp}`),
            } : null,
          });
          this.removePeer(admission.lowestPeer);
          log.info('Admission: evicted lower-priority peer via REDIRECT', {
            evicted: peerTag(admission.lowestPeer),
            incoming: peerTag(nodeId),
          });
        }
      } else if (admission.verdict === -1) {
        // Incoming ≤ all connected AND no room → REDIRECT incoming to a peer with capacity
        // Send WELCOME first (plaintext handshake), then REDIRECT
        this._send(ws, {
          type: MessageTypes.WELCOME,
          identity: {
            ...this.identity.getPublicIdentity(),
            networkId: this.networkId,
            networkFingerprint: this.networkFingerprint,
          },
          capabilities: getCapabilities(),
          peers: this.getPeers().filter(p => p.nodeId !== nodeId),
        });
        this._sendRedirect(ws, nodeId, 'capacity_full');
        log.info('Admission DENY: redirected incoming peer', { peer: peerTag(nodeId), utilization: admission.utilization.toFixed(2) });
        ws.close(1000, 'Capacity full — redirected');
        return; // Don't continue HELLO processing
      } else if (admission.verdict === 0) {
        // SAMUHA HOLD — ABSTAIN band (utilization 0.8–1.0): the peer waits
        // in queue for a slot rather than being rejected. Queue full or a
        // peer already held twice → degrade to REDIRECT per spec.
        const heldBefore = msg._holdCount || 0;
        if (this._holdQueue.length >= this.config.holdQueueMax || heldBefore >= 2) {
          this._sendRedirect(ws, nodeId, this._holdQueue.length >= this.config.holdQueueMax ? 'hold_queue_full' : 'hold_exhausted');
          try { ws.close(1000, 'HOLD queue unavailable — redirected'); } catch { }
          return;
        }
        msg._holdCount = heldBefore + 1;
        this._send(ws, {
          type: MessageTypes.HOLD,
          position: this._holdQueue.length + 1,
          timeoutMs: this.config.holdTimeoutMs,
        });
        const entry = {
          ws, nodeId, msg, priority: admission.priority,
          enqueuedAt: Date.now(),
          timer: setTimeout(() => this._expireHold(entry), this.config.holdTimeoutMs),
        };
        this._holdQueue.push(entry);
        log.info('SAMUHA HOLD — peer queued pending capacity', {
          peer: peerTag(nodeId), position: this._holdQueue.length,
          priority: admission.priority.toFixed(3), utilization: admission.utilization.toFixed(2),
        });
        return; // Don't continue HELLO processing — promoted on slot-open
      }

      // Store peer — admission passed (AFFIRM, or eviction upgrade)
      // For outbound connections, use our tracked endpoint.
      // For inbound connections, use peer's advertised endpoint (so we can reconnect to them).
      // Tunnel-dialed outbound stores the peer's REAL endpoint — the vIP
      // is recomputed from nodeId at dial time and is useless without wire B.
      const peerEndpoint = ws._viaTun
        ? (msg.advertisedEndpoint || ws._outboundEndpoint || null)
        : (ws._outboundEndpoint || msg.advertisedEndpoint || null);
      this.peers.set(nodeId, {
        ws,
        wsVia: ws._viaTun ? 'tun' : 'lan',
        lifelineWs: null,
        identity: msg.identity,
        endpoint: peerEndpoint,
        capabilities: msg.capabilities || null,
        lastSeen: Date.now(),
        connectedAt: Date.now(),
        // SAMUHA admission record — verdict + composite priority at accept time
        admission: { verdict: admission.verdict, priority: admission.priority },
        // Pinned ratchet keys from the verified handshake — used to verify
        // _tribhujSig messages. Only keys bound inside the PoP proof are trusted.
        tribhujKeys: {
          current: msg.identity.tribhujPubKey || null,
          previous: msg.identity.tribhujPrevPubKey || null,
        },
      });

      // AGUWA: register peer for Kuramoto phase tracking
      if (msg.capabilities) aguwa.addPeer(nodeId, msg.capabilities);

      if (peerEndpoint && !ws._outboundEndpoint) {
        log.debug('Learned peer endpoint from inbound connection', { peer: peerTag(nodeId), endpoint: peerEndpoint });
      }

      // Release handshake slot — peer is now fully registered.
      // The slot was reserved in _handleIncomingConnection.
      if (this._pendingHandshakeWs.has(ws)) {
        this._pendingHandshakeCount = Math.max(0, this._pendingHandshakeCount - 1);
        this._pendingHandshakeWs.delete(ws);
      }

      // Send WELCOME back — this is a handshake message, always plaintext.
      // Like TLS ServerHello: the identity exchange MUST be unencrypted because
      // the initiator hasn't learned our nodeId yet and can't derive JHILKE.
      this._sendWelcome(ws, nodeId);

      // JHILKE: Bootstrap ANNEX session IMMEDIATELY after WELCOME send.
      // Both nodes derive the same key from codeHash + buildNonce + sorted(nodeId1, nodeId2).
      // The bootstrap session provides the initial channel — then upgrades to
      // KEM for forward secrecy (the lower nodeId initiates the upgrade).
      // This MUST happen BEFORE emit('peer-registered') so any messages triggered
      // by that event are encrypted via ANNEX — zero plaintext gap.
      if (this.annex && !this.annex.sessions.get(nodeId)) {
        if (this.jhilke) {
          const bootstrapKey = this.jhilke.deriveBootstrapKey(nodeId);
          this.annex.bootstrapSession(nodeId, bootstrapKey);
          log.info('ANNEX channel established via JHILKE bootstrap', { peerId: peerTag(nodeId) });
          // Kick off KEM upgrade for forward secrecy (tie-break inside openChannel)
          this.annex.openChannel(nodeId).catch(err => {
            log.debug('ANNEX KEM upgrade deferred/failed', { peerId: peerTag(nodeId), error: err.message });
          });
        } else {
          // No JHILKE — fall back to KEM handshake (lower nodeId initiates)
          if (ourNodeId < nodeId) {
            this.annex.openChannel(nodeId).then(() => {
              log.info('ANNEX channel established with peer (KEM)', { peerId: peerTag(nodeId) });
            }).catch(err => {
              log.warn('ANNEX negotiation failed', { peerId: peerTag(nodeId), error: err.message });
            });
          }
        }
      }

      log.info('Peer connected', { name: msg.identity.name, peer: peerTag(nodeId), totalPeers: this.peers.size });

      // Signal that this peer's public key is now available — any deferred
      // ANNEX messages waiting for this key will be replayed.
      // JHILKE is already established above, so event listeners will encrypt.
      this.emit('peer-registered', nodeId);
    });

    // Handle WELCOME
    this.on(MessageTypes.WELCOME, (msg, ws) => {
      const nodeId = msg.identity.nodeId;

      // MITM DETECTION: If we connected to a known nodeId (via gossip/SHERPA),
      // verify the responding node is who we expected. A MITM at the endpoint
      // would respond with a different nodeId — reject immediately.
      if (ws._targetNodeId && nodeId !== ws._targetNodeId) {
        log.warn('MITM detected — WELCOME nodeId does not match expected target', {
          expected: peerTag(ws._targetNodeId),
          actual: peerTag(nodeId),
          endpoint: ws._outboundEndpoint,
        });
        ws.close(1008, 'NodeId mismatch — possible MITM');
        if (ws._pendingWelcome) {
          ws._pendingWelcome({ rejected: true, reason: 'MITM_NODEID_MISMATCH' });
          delete ws._pendingWelcome;
        }
        return;
      }

      // REPLAY PROTECTION: timestamp must be within a 5-minute window
      if (!msg.timestamp || Math.abs(Date.now() - msg.timestamp) > 5 * 60 * 1000) {
        log.warn('Rejected WELCOME — stale or missing timestamp', { peer: peerTag(nodeId) });
        ws.close(1008, 'Stale handshake timestamp');
        if (ws._pendingWelcome) {
          ws._pendingWelcome({ rejected: true, reason: 'STALE_TIMESTAMP' });
          delete ws._pendingWelcome;
        }
        return;
      }

      // PROOF OF POSSESSION: Verify the responder controls the claimed private key.
      // The WELCOME must include a signature of
      // "YAKMESH:WELCOME:{nodeId}:{timestamp}:{tribhujPubKey}" under the claimed
      // publicKey. The ratchet key is bound inside the proof.
      const welcomePubKey = msg.identity?.publicKey;
      const claimedTribhujW = msg.identity?.tribhujPubKey || '';
      const welcomeProofPayload = `YAKMESH:WELCOME:${nodeId}:${msg.timestamp}:${claimedTribhujW}`;
      if (!welcomePubKey || !msg.proof || !this.identity.verify(welcomeProofPayload, msg.proof, welcomePubKey)) {
        log.warn('Rejected WELCOME — invalid proof of possession', {
          peer: peerTag(nodeId),
          hasPubKey: !!welcomePubKey,
          hasProof: !!msg.proof,
        });
        ws.close(1008, 'Proof of possession failed');
        if (ws._pendingWelcome) {
          ws._pendingWelcome({ rejected: true, reason: 'PROOF_OF_POSSESSION_FAILED' });
          delete ws._pendingWelcome;
        }
        return;
      }

      // IDENTITY BINDING: nodeId must be derived from the claimed publicKey.
      try {
        const derivedWelcomeId = generateNodeId(hexToBytes(welcomePubKey));
        if (derivedWelcomeId !== nodeId) {
          log.warn('Rejected WELCOME — nodeId not bound to publicKey', {
            claimed: peerTag(nodeId),
            derived: peerTag(derivedWelcomeId),
          });
          ws.close(1008, 'Identity binding failed');
          if (ws._pendingWelcome) {
            ws._pendingWelcome({ rejected: true, reason: 'IDENTITY_BINDING_FAILED' });
            delete ws._pendingWelcome;
          }
          return;
        }
      } catch (err) {
        log.warn('Rejected WELCOME — could not verify identity binding', { error: err.message });
        ws.close(1008, 'Identity binding failed');
        return;
      }

      // SELF-CONNECTION REJECT: a WELCOME carrying our own nodeId means we
      // dialed ourselves (own advertised/learned endpoint, NAT hairpin).
      if (nodeId === this.identity?.identity?.nodeId) {
        log.warn('Rejected WELCOME — self-connection (own nodeId)');
        try { ws.close(1008, 'Self-connection'); } catch { }
        if (ws._pendingWelcome) {
          ws._pendingWelcome({ rejected: true, reason: 'SELF_CONNECTION' });
          delete ws._pendingWelcome;
        }
        return;
      }

      // CODE PROOF VERIFICATION: Check network fingerprint on WELCOME too
      // This protects the INITIATOR - even if remote accepts us, we reject them if mismatched
      if (this.networkFingerprint && msg.identity.networkFingerprint) {
        if (msg.identity.networkFingerprint !== this.networkFingerprint) {
          console.warn(`✗ Rejecting peer ${peerTag(nodeId)} - incompatible codebase (on WELCOME)`);
          console.warn(`  Their network: ${msg.identity.networkId || 'unknown'}`);
          console.warn(`  Our network:   ${this.networkId || 'unknown'}`);
          ws.close(1008, 'Incompatible codebase');

          // Signal rejection to pending promise
          if (ws._pendingWelcome) {
            ws._pendingWelcome({ rejected: true, reason: 'INCOMPATIBLE_CODEBASE' });
            delete ws._pendingWelcome;
          }
          return;
        }
      } else if (this.networkFingerprint && !msg.identity.networkFingerprint) {
        // Remote node didn't send fingerprint - they're running old code
        console.warn(`✗ Rejecting peer ${peerTag(nodeId)} - no fingerprint (old codebase)`);
        ws.close(1008, 'Missing network fingerprint');

        if (ws._pendingWelcome) {
          ws._pendingWelcome({ rejected: true, reason: 'MISSING_FINGERPRINT' });
          delete ws._pendingWelcome;
        }
        return;
      }

      // DUPLICATE / RECONNECT DETECTION (WELCOME path): same logic as HELLO.
      const existingPeerW = this.peers.get(nodeId);
      if (existingPeerW && existingPeerW.ws !== ws) {
        const oldAlive = existingPeerW.ws.readyState === WebSocket.OPEN;
        if (oldAlive) {
          // Dual-wire: our outbound dial landed on the other wire — attach
          // it as the second link instead of dropping it.
          if (this._attachSecondWire(existingPeerW, ws, nodeId)) {
            if (ws._pendingWelcome) {
              ws._pendingWelcome(msg);
              delete ws._pendingWelcome;
            }
            return;
          }
          // Existing connection is still alive — duplicate. Keep the old one.
          // Tag the existing peer with this endpoint so bootstrap's
          // connectedEndpoints check will match and stop retrying.
          if (ws._outboundEndpoint && !existingPeerW.endpoint) {
            log.info('Updating peer endpoint from duplicate outbound', {
              peer: peerTag(nodeId),
              newEndpoint: ws._outboundEndpoint
            });
            existingPeerW.endpoint = ws._outboundEndpoint;
          }
          log.info('Duplicate outbound to peer — keeping existing WS', { peer: peerTag(nodeId) });
          try { ws.close(1000, 'Duplicate connection'); } catch { }
          // Still resolve the pending promise so bootstrap doesn't retry
          if (ws._pendingWelcome) {
            ws._pendingWelcome(msg);
            delete ws._pendingWelcome;
          }
          return;
        }
        // Old WS is dead — genuine reconnect. Reset ANNEX state.
        log.info('Peer reconnected on WELCOME (new WS) — resetting ANNEX/JHILKE state', { peer: peerTag(nodeId) });
        if (this.annex) {
          this.annex.sessions.delete(nodeId);
          this.annex.pendingHandshakes.delete(nodeId);
        }
        if (this.jhilke) {
          this.jhilke.cleanupPeer(nodeId);
        }
        try { existingPeerW.ws.close(1000, 'Replaced by reconnect'); } catch { }
      }

      // Store peer — for outbound we have _outboundEndpoint, for inbound use advertised.
      // Tunnel-dialed outbound keeps the peer's REAL endpoint (see HELLO path).
      const peerEndpoint = ws._viaTun
        ? (msg.advertisedEndpoint || ws._outboundEndpoint || null)
        : (ws._outboundEndpoint || msg.advertisedEndpoint || null);
      this.peers.set(nodeId, {
        ws,
        wsVia: ws._viaTun ? 'tun' : 'lan',
        lifelineWs: null,
        identity: msg.identity,
        endpoint: peerEndpoint,
        capabilities: msg.capabilities || null,
        lastSeen: Date.now(),
        // Pinned ratchet keys from the verified handshake — used to verify
        // _tribhujSig messages. Only keys bound inside the PoP proof are trusted.
        tribhujKeys: {
          current: msg.identity.tribhujPubKey || null,
          previous: msg.identity.tribhujPrevPubKey || null,
        },
      });

      // AGUWA: register peer for Kuramoto phase tracking
      if (msg.capabilities) aguwa.addPeer(nodeId, msg.capabilities);

      if (peerEndpoint && !ws._outboundEndpoint) {
        log.debug('Learned peer endpoint from WELCOME', { peer: peerTag(nodeId), endpoint: peerEndpoint });
      }

      // JHILKE: Bootstrap ANNEX session IMMEDIATELY after storing peer.
      // Both sides now know each other's nodeId — derive the same deterministic key.
      // The bootstrap session provides the initial channel — then upgrades to
      // KEM for forward secrecy (the lower nodeId initiates the upgrade).
      // This MUST happen BEFORE the pending-welcome callback and 'peer-registered'
      // event so any messages triggered by those are encrypted — zero plaintext gap.
      const ourNodeId = this.identity.identity.nodeId;
      if (this.annex && !this.annex.sessions.get(nodeId)) {
        if (this.jhilke) {
          const bootstrapKey = this.jhilke.deriveBootstrapKey(nodeId);
          this.annex.bootstrapSession(nodeId, bootstrapKey);
          log.info('ANNEX channel established via JHILKE bootstrap (WELCOME)', { peerId: peerTag(nodeId) });
          // Kick off KEM upgrade for forward secrecy (tie-break inside openChannel)
          this.annex.openChannel(nodeId).catch(err => {
            log.debug('ANNEX KEM upgrade deferred/failed', { peerId: peerTag(nodeId), error: err.message });
          });
        } else {
          // No JHILKE — fall back to KEM handshake (lower nodeId initiates)
          if (ourNodeId < nodeId) {
            this.annex.openChannel(nodeId).then(() => {
              log.info('ANNEX channel established with peer (KEM)', { peerId: peerTag(nodeId) });
            }).catch(err => {
              log.warn('ANNEX negotiation failed', { peerId: peerTag(nodeId), error: err.message });
            });
          }
        }
      }

      // Callback for pending connection — JHILKE is now ready
      if (ws._pendingWelcome) {
        ws._pendingWelcome(msg);
        delete ws._pendingWelcome;
      }

      // Signal that this peer's public key is now available.
      // JHILKE is already established above, so event listeners will encrypt.
      this.emit('peer-registered', nodeId);
    });

    // Handle REJECT — peer rejected our connection (incompatible codebase, etc.)
    this.on('REJECT', (msg, ws) => {
      log.warn('Connection rejected by peer', {
        reason: msg.reason || 'unknown',
        theirNetwork: msg.ourNetworkId || 'unknown',
      });
      // Signal rejection to pending promise if this was an outbound connection
      if (ws._pendingWelcome) {
        ws._pendingWelcome({ rejected: true, reason: msg.reason });
        delete ws._pendingWelcome;
      }
      try { ws.close(1000, 'Rejected'); } catch { }
    });

    // Handle mesh_entropy — JHILKE cricket signals hidden in entropy exchange
    this.on('mesh_entropy', (msg, ws, senderNodeId) => {
      if (this.jhilke && senderNodeId) {
        this.jhilke.handleIncoming(senderNodeId, msg);
      }
    });

    // Handle REDIRECT — peer is forwarding us to another node with capacity
    this.on(MessageTypes.REDIRECT, (msg, ws, nodeId) => {
      log.info('Received REDIRECT from peer', {
        from: peerTag(nodeId),
        reason: msg.reason,
        suggestedPeers: msg.peers?.length || 0,
      });

      // SAMUHA — stash the signed referral token; it is bound to OUR
      // nodeId, so we present it in the next outbound HELLO to let the
      // target verify this is a legitimate redirect, not a cold probe.
      if (msg.referral && msg.referral.exp > Date.now()) {
        this._pendingReferral = msg.referral;
      }

      // Try to connect to suggested peers
      const learnedDialable = (ep) =>
        ep && !MandalaNetwork._isLoopbackHost(MandalaNetwork._endpointHost(ep));
      if (learnedDialable(msg.endpoint)) {
        this.connectToPeer(msg.endpoint).catch(() => { });
      } else if (msg.peers?.length) {
        for (const peer of msg.peers.slice(0, 3)) {
          if (learnedDialable(peer.endpoint)) {
            this.connectToPeer(peer.endpoint, peer.nodeId).catch(() => { });
          }
        }
      }
    });

    // Handle PING
    this.on(MessageTypes.PING, (msg, ws, nodeId) => {
      this._send(ws, { type: MessageTypes.PONG, timestamp: Date.now() });
    });

    // Handle PONG
    this.on(MessageTypes.PONG, (msg, ws, nodeId) => {
      // Per-socket liveness — dual-wire peers need each wire tracked
      // independently (a dead primary can't hide behind lifeline PONGs).
      ws._lastPong = Date.now();
      const peer = this.peers.get(nodeId);
      if (peer) {
        peer.lastSeen = Date.now();
      }
    });

    // Handle GOSSIP
    this.on(MessageTypes.GOSSIP, (msg, ws, nodeId) => {
      // Deduplicate
      if (this.seenMessages.has(msg.id)) {
        log.debug('GOSSIP dedup — already seen', { id: msg.id?.slice(0, 12) });
        return;
      }
      this.seenMessages.add(msg.id);

      // TTL check
      if (msg.ttl <= 0) {
        log.debug('GOSSIP TTL expired', { id: msg.id?.slice(0, 12) });
        return;
      }

      // Check for gossip protocol message
      if (msg.payload && msg.payload.gossip) {
        this.emit('gossip', msg.payload.gossip, nodeId);
      }

      // App-level broadcast payloads (seva:capability, beacon, content:*)
      // carry their own type inside the gossip envelope — dispatch to
      // handlers registered for that inner type. Without this the envelope
      // type 'gossip' swallows every app broadcast. Sender is the origin.
      const innerType = msg.payload?.type;
      if (innerType && innerType !== MessageTypes.GOSSIP) {
        const handlers = this.messageHandlers.get(innerType) || [];
        for (const handler of handlers) {
          try {
            handler(msg.payload, ws, msg.origin || nodeId);
          } catch (err) {
            log.warn('GOSSIP inner dispatch error', { type: innerType, error: err.message });
          }
        }
      }

      // Forward to other WS peers
      const forwardMsg = { ...msg, ttl: msg.ttl - 1 };
      for (const [peerId, peer] of this.peers) {
        if (peerId !== nodeId && peerId !== msg.origin) {
          this._send(peer.ws, forwardMsg);
        }
      }

      // Also forward to HTTP relay peers (server layer hooks this)
      this.emit('outbound-gossip', forwardMsg, [nodeId, msg.origin]);
    });
  }

  _handleIncomingConnection(ws, req) {
    const clientIp = req.socket.remoteAddress || 'unknown';
    ws._clientIp = clientIp; // preserved for SAMUHA HOLD re-dispatch
    // Sockets arriving from the tunnel subnet are overlay links — they ride
    // wire B (UDP underlay) and must never carry TUN_PACKETs (recursion).
    if (MandalaNetwork._isTunnelIp(clientIp)) ws._viaTun = true;
    log.debug('Incoming connection', { clientIp });

    // SECURITY: Rate limit check for connection flood protection (per-IP)
    const connectionCheck = this.rateLimiter.checkConnection(clientIp);
    if (!connectionCheck.allowed) {
      console.warn(`⚠️ Connection rejected (rate limit): ${clientIp} - ${connectionCheck.reason}`);
      ws.close(1008, connectionCheck.reason);
      return;
    }

    // SECURITY: Concurrent handshake gate — limits how many peers can be
    // negotiating HELLO/WELCOME simultaneously. Total peers is unbounded;
    // only the handshake window is capped. A burst of connections from
    // many IPs at once is a Sybil tell.
    if (this._pendingHandshakeCount >= this.config.maxConcurrentHandshakes) {
      log.warn('Connection rejected (handshake slots full)', {
        clientIp,
        pending: this._pendingHandshakeCount,
        max: this.config.maxConcurrentHandshakes,
      });
      ws.close(1013, 'Try again later — handshake slots full');
      return;
    }

    // Track this connection as pending handshake
    this._pendingHandshakeCount++;
    this._pendingHandshakeWs.add(ws);

    // SECURITY: Burst detection — track connection rate in sliding window.
    // GPS-timestamped evidence for Sybil forensics.
    this._recordConnectionBurst(clientIp);

    ws.on('message', (data) => {
      this._handleMessage(ws, data, req);
    });

    ws.on('close', () => {
      // Release handshake slot if peer disconnects before completing HELLO
      if (this._pendingHandshakeWs.has(ws)) {
        this._pendingHandshakeCount = Math.max(0, this._pendingHandshakeCount - 1);
        this._pendingHandshakeWs.delete(ws);
      }
      this._handleDisconnect(ws);
    });

    ws.on('error', (err) => {
      console.error('Peer error:', err.message);
    });
  }

  _handleMessage(ws, data, req) {
    try {
      const rawStr = data.toString();

      // STAGE 1: Raw size validation — reject before parsing
      const rawCheck = this.messageValidator.validateRaw(rawStr);
      if (!rawCheck.valid) {
        log.warn('Rejected oversized WS message', { reason: rawCheck.reason, size: rawStr.length });
        return;
      }

      // STAGE 2: Safe JSON parse — proto pollution guard + size check
      const parseResult = this.safeJsonParser.parse(rawStr);
      if (!parseResult.success) {
        log.warn('Rejected malformed WS message', { error: parseResult.error });
        return;
      }
      const msg = parseResult.data;

      // STAGE 3: Structure validation — depth, array length, required fields
      const msgType = msg.type || 'gossip';
      const structCheck = this.messageValidator.validateStructure(msg, msgType);
      if (!structCheck.valid) {
        log.warn('Rejected invalid WS message structure', { reason: structCheck.reason, type: msgType });
        return;
      }

      // Find nodeId for this connection — matches the primary socket or
      // the lifeline (dual-wire second link).
      let senderNodeId = null;
      let senderPublicKey = null;
      for (const [nodeId, peer] of this.peers) {
        if (peer.ws === ws || peer.lifelineWs === ws) {
          senderNodeId = nodeId;
          senderPublicKey = peer.identity?.publicKey;
          peer.lastSeen = Date.now();
          ws._lastRx = Date.now();
          break;
        }
      }

      // SECURITY: Verify signatures on messages from known peers
      // Priority: (1) gateway attestation (fast), (2) TRIBHUJ ratchet, (3) legacy identity

      // Check for gateway attestation first — "verify once, trust the stamp"
      if (msg._gwAttest && this.gateway) {
        // Pin check: the attesting gateway must be a connected peer whose
        // ratchet key was bound in the verified handshake.
        const gwPeer = this.peers.get(msg._gwAttest.gateway);
        const attestResult = this.gateway.verifyAttestation(msg._gwAttest, gwPeer?.tribhujKeys || null);
        if (attestResult.valid) {
          // Attestation valid — skip expensive ML-DSA-65 verify (~0.01ms vs ~2-5ms)
          log.debug('Accepted via gateway attestation', {
            type: msg.type,
            gateway: peerTag(msg._gwAttest.gateway),
          });
        } else {
          // Attestation invalid — still try full verification below
          log.debug('Gateway attestation invalid, falling back to full verify', {
            reason: attestResult.reason,
          });
          msg._gwAttest = null; // Clear bad attestation
        }
      }

      // TRIBHUJ ratchet verification (rotating keys)
      if (msg._tribhujSig && !msg._gwAttest?.hash) {
        // Dual-wire: on a second-wire socket the handshake hasn't run yet, so
        // the socket isn't mapped to a peer — but an ANNEX envelope carries
        // its (signed) senderId in the clear. Verify the hop signature
        // against that claimed peer's pinned keys instead of dropping.
        const effectiveSender = senderNodeId || msg.annex?.senderId || null;
        const peer = effectiveSender ? this.peers.get(effectiveSender) : null;
        const pinned = peer?.tribhujKeys;
        const claimedKey = msg._tribhujPubKey;

        // The message's ratchet key MUST be one of the keys pinned during the
        // authenticated handshake — OR be certified by the peer's pinned
        // identity key (rotation certificate).
        let ratchetKeyValid = false;
        if (pinned && claimedKey &&
            (claimedKey === pinned.current || claimedKey === pinned.previous)) {
          ratchetKeyValid = true;
        } else if (msg._tribhujCert && claimedKey && peer?.identity?.publicKey) {
          // Rotation cert: identity key signs "YAKMESH:TRIBHUJ-KEY:{nodeId}:{newKey}:{epoch}"
          const certPayload = `YAKMESH:TRIBHUJ-KEY:${effectiveSender}:${claimedKey}:${msg._tribhujEpoch}`;
          if (this.identity.verify(certPayload, msg._tribhujCert, peer.identity.publicKey)) {
            ratchetKeyValid = true;
            // Advance the pinned set — chain moved forward
            peer.tribhujKeys = { current: claimedKey, previous: pinned?.current || null };
            log.debug('TRIBHUJ rotation certified by identity key', { peer: peerTag(effectiveSender) });
          }
        }

        if (!ratchetKeyValid) {
          log.warn('Rejected message — ratchet key not pinned or certified', {
            type: msg.type,
            sender: peerTag(effectiveSender),
            hasPinned: !!pinned,
          });
          return; // Drop forged message
        }

        // Verify signature under the pinned/certified ratchet key.
        // Payload excludes the sig fields + the cert (cert is added post-signing).
        const { _tribhujSig, _tribhujEpoch, _tribhujPubKey, _tribhujCert, ...rest } = msg;
        const result = {
          valid: false,
          keyState: 'invalid',
        };
        try {
          const ok = this.identity.verify(JSON.stringify(rest), _tribhujSig, claimedKey);
          result.valid = ok;
          result.keyState = ok ? 'pinned' : 'invalid';
        } catch (e) { /* result stays invalid */ }

        if (!result.valid) {
          log.warn('Rejected message with invalid TRIBHUJ signature', {
            type: msg.type,
            epoch: msg._tribhujEpoch,
            keyState: result.keyState,
            sender: peerTag(effectiveSender),
          });
          return; // Drop forged message
        }

        // If we're also a gateway, attest this for downstream peers
        if (this.gateway && msg.type === MessageTypes.GOSSIP && msg.id) {
          msg._gwAttest = this.gateway.attest(msg.id, msg.origin || senderNodeId);
        }
      }
      // Legacy identity verification (permanent key, no ratchet)
      else if (msg._signature && senderPublicKey && !msg._gwAttest?.hash) {
        // _signer is inside the signed payload — it must match the connection
        // peer, otherwise a peer could attribute their messages to another node.
        if (msg._signer && msg._signer !== senderNodeId) {
          log.warn('Rejected message — _signer does not match connection peer', {
            type: msg.type,
            claimed: peerTag(msg._signer),
            actual: peerTag(senderNodeId),
          });
          return;
        }
        const verified = this.identity.verifyObject(msg, senderPublicKey);
        if (!verified) {
          log.warn('Rejected message with invalid signature', {
            type: msg.type,
            signer: peerTag(msg._signer),
            sender: peerTag(senderNodeId),
          });
          return; // Drop forged message
        }

        // Attest for downstream if we have a gateway
        if (this.gateway && msg.type === MessageTypes.GOSSIP && msg.id) {
          msg._gwAttest = this.gateway.attest(msg.id, msg.origin || senderNodeId);
        }
      } else if (msg._signature && !senderPublicKey) {
        // Signed message from unknown peer — might be HELLO/WELCOME flow
        // Allow through since the handshake handler validates identity
        log.debug('Signed message from unregistered peer, passing through', { type: msg.type });
      } else if (!msg._gwAttest && !msg._tribhujSig && !msg._signature) {
        // UNSIGNED message — allow handshake types (HELLO/WELCOME/REJECT) and
        // rumor-carrying gossip wrappers. Rumors are authenticated end-to-end
        // at the gossip layer (rumor.signature, or data.signature on the
        // self-signed path); the ANNEX session authenticates the hop. All
        // other message types from known peers MUST be signed.
        const isRumorWrapper = msg.type === MessageTypes.GOSSIP &&
          msg.payload?.gossip?.type === 'GOSSIP_RUMOR';
        const HANDSHAKE_TYPES = new Set([MessageTypes.HELLO, MessageTypes.WELCOME, MessageTypes.REDIRECT, 'REJECT']);
        if (!HANDSHAKE_TYPES.has(msg.type) && !isRumorWrapper) {
          log.warn('Rejected unsigned message from peer', {
            type: msg.type,
            sender: peerTag(senderNodeId) || 'unknown',
          });
          return; // Drop unsigned non-handshake message
        }
      }

      // Dispatch to handlers
      const handlers = this.messageHandlers.get(msg.type) || [];
      for (const handler of handlers) {
        handler(msg, ws, senderNodeId);
      }

      // Route ANNEX messages — extract envelope and pass correctly
      if (msg.annex && this.annex) {
        this.annex._handleAnnexMessage(msg.annex, senderNodeId).catch(err => {
          log.warn('ANNEX message handling error', { error: err.message });
        });
      }
    } catch (e) {
      console.error('Failed to parse message:', e.message);
    }
  }

  _handleDisconnect(ws) {
    // SAMUHA: drop any HOLD-queue entries waiting on this socket
    for (let i = this._holdQueue.length - 1; i >= 0; i--) {
      if (this._holdQueue[i].ws === ws) {
        clearTimeout(this._holdQueue[i].timer);
        this._holdQueue.splice(i, 1);
      }
    }
    let freed = false;
    for (const [nodeId, peer] of this.peers) {
      // Second-wire socket closed — the peer survives on its primary.
      if (peer.lifelineWs === ws) {
        peer.lifelineWs = null;
        log.info('Lifeline wire closed', { name: peer.identity.name, peer: peerTag(nodeId) });
        return;
      }
      if (peer.ws === ws) {
        // Primary wire died but the lifeline is up — promote instead of
        // tearing the peer down. ANNEX/JHILKE state is per-nodeId and stays.
        if (peer.lifelineWs && peer.lifelineWs.readyState === WebSocket.OPEN) {
          peer.ws = peer.lifelineWs;
          peer.wsVia = peer.wsVia === 'tun' ? 'lan' : 'tun';
          peer.lifelineWs = null;
          log.info('Wire failover — lifeline promoted to primary', {
            name: peer.identity.name, peer: peerTag(nodeId), nowVia: peer.wsVia,
          });
          return;
        }
        log.info('Peer disconnected', { name: peer.identity.name });
        // Sync ANNEX cleanup — peer is gone, no CLOSE notification needed.
        // Using async closeChannel here caused a race: if a reconnect
        // created a new bootstrap session before closeChannel's microtask
        // ran, it would delete the NEW session. Sync delete avoids this.
        if (this.annex) {
          const session = this.annex.sessions.get(nodeId);
          if (session) session.channelState = ChannelState.CLOSED;
          this.annex.sessions.delete(nodeId);
          this.annex.pendingHandshakes.delete(nodeId);
        }
        // Clean up JHILKE state for departing peer
        if (this.jhilke) {
          this.jhilke.cleanupPeer(nodeId);
        }
        // Clean up AGUWA phase tracking for departing peer
        aguwa.removePeer(nodeId);
        this.peers.delete(nodeId);
        freed = true;
        // Signal so deferred ANNEX messages for this peer are cleaned up
        this.emit('peer-disconnected', nodeId);
        break;
      }
    }
    // SAMUHA: a slot opened — promote the head of the HOLD queue
    if (freed) this._promoteHoldQueue();
  }

  /**
   * WELCOME sender — proof-of-possession handshake response.
   * "YAKMESH:WELCOME:{nodeId}:{timestamp}:{tribhujPubKey}" under our key.
   * Extracted so the dual-wire attach path can answer a second-wire HELLO
   * without re-running admission/registration.
   */
  _sendWelcome(ws, nodeId) {
    const welcomeTimestamp = Date.now();
    const ourNodeId = this.identity.identity.nodeId;
    const ourTribhuj = this.ratchet?._current?.publicKey
      ? bytesToHex(this.ratchet._current.publicKey) : null;
    const ourTribhujPrev = this.ratchet?._previous?.publicKey
      ? bytesToHex(this.ratchet._previous.publicKey) : null;
    const welcomeProof = this.identity.sign(`YAKMESH:WELCOME:${ourNodeId}:${welcomeTimestamp}:${ourTribhuj || ''}`);
    if (!this._announcedRatchetKeys) this._announcedRatchetKeys = new Set();
    if (ourTribhuj) this._announcedRatchetKeys.add(ourTribhuj);
    if (ourTribhujPrev) this._announcedRatchetKeys.add(ourTribhujPrev);
    this._send(ws, {
      type: MessageTypes.WELCOME,
      identity: {
        ...this.identity.getPublicIdentity(),
        tribhujPubKey: ourTribhuj,
        tribhujPrevPubKey: ourTribhujPrev,
        networkId: this.networkId,
        networkFingerprint: this.networkFingerprint,
      },
      advertisedEndpoint: this._getAdvertisedEndpoint(),
      capabilities: getCapabilities(),
      peers: this.getPeers().filter(p => p.nodeId !== nodeId),
      timestamp: welcomeTimestamp,
      proof: welcomeProof,
    });
  }

  /**
   * Dual-wire attach: a verified second socket for an already-connected
   * peer on the OTHER wire (lan <-> tun). The tunnel wire carries session
   * traffic (more opaque), so a tun socket promotes to primary and the
   * existing socket demotes to lifeline; a lan socket arriving while tun
   * is primary becomes the lifeline. Returns true when handled.
   */
  _attachSecondWire(existingPeer, ws, nodeId) {
    const newIsTun = !!ws._viaTun;
    const curIsTun = existingPeer.wsVia === 'tun';
    if (newIsTun === curIsTun) return false; // same wire → ordinary duplicate

    if (newIsTun) {
      // Overlay promoted to primary; existing LAN socket becomes lifeline.
      if (existingPeer.lifelineWs) { try { existingPeer.lifelineWs.close(1000, 'Lifeline replaced'); } catch { } }
      existingPeer.lifelineWs = existingPeer.ws;
      existingPeer.ws = ws;
      existingPeer.wsVia = 'tun';
    } else {
      // New LAN socket under a tun primary → lifeline only.
      if (existingPeer.lifelineWs) { try { existingPeer.lifelineWs.close(1000, 'Lifeline replaced'); } catch { } }
      existingPeer.lifelineWs = ws;
    }
    ws._targetNodeId = nodeId; // lets _send's ANNEX lookup hit this socket
    log.info('Dual-wire link attached', {
      peer: peerTag(nodeId),
      role: newIsTun ? 'primary(tun)' : 'lifeline(lan)',
    });
    return true;
  }

  /**
   * SAMUHA — send REDIRECT with suggested peers and a signed referral
   * token. The referral binds (referredNodeId ‖ expiry) under our key;
   * the target node verifies it if it knows us, preventing open-season
   * redirect abuse.
   */
  _sendRedirect(ws, nodeId, reason) {
    const exp = Date.now() + 60000;
    const referral = this.identity?.sign
      ? { by: this.identity.identity.nodeId, exp, sig: this.identity.sign(`YAKMESH:REFERRAL:${nodeId}:${exp}`) }
      : null;
    this._send(ws, {
      type: MessageTypes.REDIRECT,
      reason,
      peers: this.getPeers().slice(0, 3), // Suggest top 3 peers
      referral,
    });
  }

  /** HOLD timeout — the queued peer degrades to REDIRECT per spec. */
  _expireHold(entry) {
    const idx = this._holdQueue.indexOf(entry);
    if (idx === -1) return; // already promoted or disconnected
    this._holdQueue.splice(idx, 1);
    log.info('SAMUHA HOLD timeout — redirecting queued peer', {
      peer: peerTag(entry.nodeId), waitedMs: Date.now() - entry.enqueuedAt,
    });
    this._sendRedirect(entry.ws, entry.nodeId, 'hold_timeout');
    try { entry.ws.close(1000, 'HOLD timeout — redirected'); } catch { }
  }

  /**
   * Slot opened — re-dispatch the head of the HOLD queue through the
   * normal HELLO pipeline. The message re-verifies fresh (signatures,
   * timestamps, binding) and the admission verdict re-evaluates against
   * current utilization — no stale state, no bypass.
   */
  _promoteHoldQueue() {
    while (this._holdQueue.length > 0) {
      const entry = this._holdQueue.shift();
      clearTimeout(entry.timer);
      if (entry.ws.readyState !== WebSocket.OPEN) continue;
      log.info('SAMUHA HOLD — promoting queued peer', {
        peer: peerTag(entry.nodeId), waitedMs: Date.now() - entry.enqueuedAt,
      });
      const stubReq = { socket: { remoteAddress: entry.ws._clientIp || 'unknown' } };
      this._handleMessage(entry.ws, Buffer.from(JSON.stringify(entry.msg)), stubReq);
      return; // one promotion per freed slot — the verdict re-gates the rest
    }
  }

  _send(ws, message) {
    if (ws.readyState !== WebSocket.OPEN) return;

    // Opportunistic ANNEX encryption: if we have an active session
    // for this peer, encrypt the message transparently.
    // This ensures gossip, broadcast, ping — ALL traffic — is encrypted on the wire.
    // SKIP for ANNEX control messages (type 'annex') to prevent infinite recursion:
    //   _send → annex.send → _sendToMesh → mesh.sendTo → _send → ...
    // Also plaintext-only for handshake types — see HANDSHAKE_PLAINTEXT_TYPES.
    if (this.annex && message.type !== 'annex' && !HANDSHAKE_PLAINTEXT_TYPES.has(message.type)) {
      // Reverse-lookup nodeId from ws (primary path)
      let targetNodeId = null;
      for (const [nodeId, peer] of this.peers) {
        if (peer.ws === ws || peer.lifelineWs === ws) {
          targetNodeId = nodeId;
          break;
        }
      }

      // Defense-in-depth: if peers map lookup misses (edge case during
      // reconnect race), fall back to ws._targetNodeId from connect()
      if (!targetNodeId && ws._targetNodeId) {
        targetNodeId = ws._targetNodeId;
      }

      if (targetNodeId) {
        const session = this.annex.sessions.get(targetNodeId);
        if (session?.established && !session.isExpired()) {
          // Socket-pinned send — dual-wire semantics require the message to
          // leave on THIS socket. annex.send() would re-route through
          // sendTo → the peer's primary socket, silently switching wires.
          try {
            this.annex.sendOn(targetNodeId, message, ws);
          } catch (err) {
            // HARD FAIL: No plaintext fallback. Encryption is mandatory per Yakmesh ethos.
            // Peer must re-negotiate ANNEX session. Dropping message is safer than leaking it.
            log.error('ANNEX send failed — message dropped (no plaintext fallback)', {
              peer: peerTag(targetNodeId), error: err.message
            });
          }
          return;
        }
      }
    }

    // Plaintext only for ANNEX handshake messages (type 'annex') and initial
    // HELLO/WELCOME before ANNEX is established. Once ANNEX exists for a
    // peer, ALL traffic MUST go through it.
    ws.send(JSON.stringify(message));
  }

  _startPingLoop() {
    this._pingInterval = setInterval(() => {
      const now = Date.now();
      for (const [nodeId, peer] of this.peers) {
        // Dual-wire lifeline: heartbeat on BOTH sockets. Each wire is
        // tracked by its own last-rx/last-PONG stamp — asymmetric failure
        // detection, so a dead primary can't hide behind lifeline traffic.
        const staleAfter = this.config.pingInterval * 3;
        const sockFresh = (s) =>
          now - Math.max(s?._lastPong || 0, s?._lastRx || 0, peer.connectedAt || 0) < staleAfter;
        if (peer.lifelineWs) {
          const lw = peer.lifelineWs;
          if (lw.readyState === WebSocket.OPEN && sockFresh(lw)) {
            this._send(lw, { type: MessageTypes.PING, timestamp: now });
          } else {
            try { lw.close(); } catch { }
            peer.lifelineWs = null;
            log.info('Lifeline wire dropped', { peer: peerTag(nodeId) });
          }
        }
        // Check for stale connections — per-socket, not just peer-level.
        const primaryFresh = sockFresh(peer.ws);
        if (!primaryFresh || now - peer.lastSeen > staleAfter) {
          if (peer.lifelineWs && peer.lifelineWs.readyState === WebSocket.OPEN) {
            // Primary wire timed out but the lifeline is alive — promote it
            // rather than dropping the peer outright.
            log.warn('Primary wire timeout — promoting lifeline', {
              name: peer.identity.name, from: peer.wsVia,
            });
            try { peer.ws.close(); } catch { }
            peer.ws = peer.lifelineWs;
            peer.wsVia = peer.wsVia === 'tun' ? 'lan' : 'tun';
            peer.lifelineWs = null;
            peer.lastSeen = now;
            continue;
          }
          log.warn('Peer timeout', { name: peer.identity.name });
          peer.ws.close();
          this.peers.delete(nodeId);
        } else {
          this._send(peer.ws, { type: MessageTypes.PING, timestamp: now });
        }
      }

      // LRU eviction — keep newest half instead of clearing all (prevents dedup bypass window)
      if (this.seenMessages.size > 10000) {
        const entries = [...this.seenMessages];
        const keepCount = Math.floor(entries.length / 2);
        this.seenMessages = new Set(entries.slice(entries.length - keepCount));
      }
    }, this.config.pingInterval);
  }

  /**
   * Record a connection in the burst detection sliding window.
   * When connections/minute exceeds _burstThreshold, emits a GPS-timestamped
   * alert — the "bright spot on the map" that makes Sybil floods visible.
   * @param {string} ip - Client IP address
   */
  _recordConnectionBurst(ip) {
    const now = Date.now();

    // Add to sliding window
    this._burstWindow.push({ ts: now, ip });

    // Evict entries older than window
    const cutoff = now - this._burstWindowMs;
    while (this._burstWindow.length > 0 && this._burstWindow[0].ts < cutoff) {
      this._burstWindow.shift();
    }

    const rate = this._burstWindow.length;  // connections in last 60s

    // Track peak
    if (rate > this._burstStats.peakRate) {
      this._burstStats.peakRate = rate;
    }

    if (rate >= this._burstThreshold && !this._burstAlerted) {
      // Count unique IPs in burst
      const uniqueIps = new Set(this._burstWindow.map(e => e.ip)).size;

      this._burstAlerted = true;
      this._burstStats.totalBurstsDetected++;
      this._burstStats.lastBurstAt = new Date().toISOString();
      this._burstStats.lastBurstRate = rate;

      console.warn(`🛰️ BURST DETECTED: ${rate} connections/min (threshold: ${this._burstThreshold}) from ${uniqueIps} unique IPs`);
      log.warn('Connection burst detected — possible Sybil flood', {
        connectionsPerMinute: rate,
        threshold: this._burstThreshold,
        uniqueIps,
        pendingHandshakes: this._pendingHandshakeCount,
        totalPeers: this.peers.size,
        // GPS-precision timestamp for forensic evidence
        gpsTimestamp: new Date().toISOString(),
        // IP frequency distribution (top 5 offenders)
        topIps: this._getTopBurstIps(5),
      });

      // Emit event for external consumers (health endpoint, SAKSHI anomaly detection)
      this.emit('connection-burst', {
        rate,
        uniqueIps,
        topIps: this._getTopBurstIps(5),
        timestamp: new Date().toISOString(),
      });

      // Reset alert after 30s (allow re-triggering if burst continues)
      clearTimeout(this._burstAlertTimeout);
      this._burstAlertTimeout = setTimeout(() => { this._burstAlerted = false; }, 30000);
    }
  }

  /**
   * Get the top N most frequent IPs in the current burst window.
   * @param {number} n - Number of top IPs to return
   * @returns {Array<{ip: string, count: number}>}
   */
  _getTopBurstIps(n = 5) {
    const counts = new Map();
    for (const entry of this._burstWindow) {
      counts.set(entry.ip, (counts.get(entry.ip) || 0) + 1);
    }
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([ip, count]) => ({ ip, count }));
  }

  /**
   * Security stats for /health endpoint exposure.
   * Provides visibility into handshake pressure and burst detection.
   */
  getSecurityStats() {
    return {
      pendingHandshakes: this._pendingHandshakeCount,
      maxConcurrentHandshakes: this.config.maxConcurrentHandshakes,
      totalConnectedPeers: this.peers.size,
      burstDetection: {
        currentRate: this._burstWindow.length,
        threshold: this._burstThreshold,
        windowMs: this._burstWindowMs,
        inBurst: this._burstAlerted,
        stats: { ...this._burstStats },
      },
    };
  }
}

// ============================================================
// EXPORTS - MANDALA naming with backward compatibility
// ============================================================

// Note: MandalaMessageTypes and MandalaNetwork already exported at declarations
// Backward compatibility exports (original naming)
export { MandalaNetwork as MeshNetwork };

export default MandalaNetwork;
