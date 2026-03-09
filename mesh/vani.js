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
 * VANI - Voice And Networked Interaction
 * 
 * WebRTC voice and video calling for Yakmesh:
 * - Peer-to-peer media streams (no central server)
 * - Mesh network signaling (SDP offer/answer, ICE candidates)
 * - Call state management (ringing, connected, ended)
 * - Multi-party calls via mesh relay
 * - Integration with GUMBA for private room calls
 * 
 * Etymology: वाणी (vani) = voice, speech in Sanskrit
 * 
 * WebRTC provides the actual media transport; VANI handles:
 * 1. Signaling through the mesh network
 * 2. Call lifecycle (initiate, accept, reject, end)
 * 3. Participant management for group calls
 * 4. STUN/TURN configuration
 * 
 * @module mesh/vani
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { randomBytes } from 'crypto';
import { bytesToHex } from '@noble/hashes/utils.js';

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

export const VANI_CONFIG = Object.freeze({
  // Call settings
  callTimeout: 30000,              // Ring timeout (30 seconds)
  iceGatheringTimeout: 10000,      // ICE gathering timeout
  reconnectTimeout: 15000,         // Reconnect attempt window
  maxParticipants: 10,             // Max participants in group call
  
  // ICE servers for NAT traversal
  // ⚠️ ETHOS: Empty by default — Yakmesh mesh relay is preferred
  // For hybrid deployments, configure your own STUN/TURN servers:
  //   iceServers: [{ urls: 'stun:your.stun.server:3478' }]
  iceServers: [],
  
  // Mesh relay settings (preferred over external STUN/TURN)
  meshRelayEnabled: true,
  meshRelayTimeout: 5000,  // Try mesh relay after 5s of ICE failure
  
  // Message types
  messageTypes: {
    // Call setup
    CALL_OFFER: 'vani:call:offer',
    CALL_ANSWER: 'vani:call:answer',
    CALL_REJECT: 'vani:call:reject',
    CALL_END: 'vani:call:end',
    CALL_BUSY: 'vani:call:busy',
    
    // WebRTC signaling
    SDP_OFFER: 'vani:sdp:offer',
    SDP_ANSWER: 'vani:sdp:answer',
    ICE_CANDIDATE: 'vani:ice:candidate',
    
    // Call control
    MUTE_AUDIO: 'vani:mute:audio',
    MUTE_VIDEO: 'vani:mute:video',
    SCREEN_SHARE_START: 'vani:screen:start',
    SCREEN_SHARE_STOP: 'vani:screen:stop',
    
    // Group calls
    PARTICIPANT_JOIN: 'vani:participant:join',
    PARTICIPANT_LEAVE: 'vani:participant:leave',
    PARTICIPANT_LIST: 'vani:participant:list',
  },
  
  // Media constraints
  defaultConstraints: {
    audio: {
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true,
    },
    video: {
      width: { ideal: 1280, max: 1920 },
      height: { ideal: 720, max: 1080 },
      frameRate: { ideal: 30, max: 60 },
    },
  },
});

// ═══════════════════════════════════════════════════════════════════════════════
// CALL STATES
// ═══════════════════════════════════════════════════════════════════════════════

export const CALL_STATE = Object.freeze({
  IDLE: 'idle',
  INITIATING: 'initiating',     // Creating offer
  RINGING: 'ringing',           // Waiting for answer
  INCOMING: 'incoming',         // Received call
  CONNECTING: 'connecting',     // Exchanging ICE
  CONNECTED: 'connected',       // Media flowing
  RECONNECTING: 'reconnecting', // Temporary disconnect
  ENDED: 'ended',               // Call terminated
  FAILED: 'failed',             // Call failed
});

export const CALL_END_REASON = Object.freeze({
  NORMAL: 'normal',             // Normal hangup
  REJECTED: 'rejected',         // Callee rejected
  BUSY: 'busy',                 // Callee busy
  TIMEOUT: 'timeout',           // No answer
  FAILED: 'failed',             // Connection failed
  NETWORK_ERROR: 'network',     // Network issue
  PARTICIPANT_LEFT: 'left',     // Participant left group
});

export const MEDIA_TYPE = Object.freeze({
  AUDIO: 'audio',
  VIDEO: 'video',
  SCREEN: 'screen',
});

// ═══════════════════════════════════════════════════════════════════════════════
// VANI PARTICIPANT - Individual call participant
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * VaniParticipant - Represents a participant in a call
 */
export class VaniParticipant {
  constructor(options = {}) {
    this.id = options.id || VaniParticipant.generateId();
    this.peerId = options.peerId;           // Mesh node ID
    this.displayName = options.displayName || options.peerId;
    this.joinedAt = options.joinedAt || Date.now();
    
    // Media state
    this.audioEnabled = options.audioEnabled !== false;
    this.videoEnabled = options.videoEnabled !== false;
    this.screenSharing = options.screenSharing || false;
    
    // Connection state
    this.connectionState = options.connectionState || 'new';
    this.iceConnectionState = options.iceConnectionState || 'new';
    
    // WebRTC peer connection (set externally)
    this.peerConnection = null;
    this.localStream = null;
    this.remoteStream = null;
  }

  static generateId() {
    return 'p-' + bytesToHex(randomBytes(8));
  }

  toJSON() {
    return {
      id: this.id,
      peerId: this.peerId,
      displayName: this.displayName,
      joinedAt: this.joinedAt,
      audioEnabled: this.audioEnabled,
      videoEnabled: this.videoEnabled,
      screenSharing: this.screenSharing,
      connectionState: this.connectionState,
      iceConnectionState: this.iceConnectionState,
    };
  }

  static fromJSON(json) {
    return new VaniParticipant(json);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VANI SIGNAL - Signaling message
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * VaniSignal - A signaling message for call setup
 */
export class VaniSignal {
  constructor(options = {}) {
    this.id = options.id || VaniSignal.generateId();
    this.type = options.type;
    this.callId = options.callId;
    this.fromPeer = options.fromPeer;
    this.toPeer = options.toPeer;         // null for broadcast in group
    this.timestamp = options.timestamp || Date.now();
    this.payload = options.payload || {};
  }

  static generateId() {
    return 's-' + bytesToHex(randomBytes(8));
  }

  /**
   * Create a call offer signal
   */
  static offer(options) {
    return new VaniSignal({
      type: VANI_CONFIG.messageTypes.CALL_OFFER,
      callId: options.callId,
      fromPeer: options.fromPeer,
      toPeer: options.toPeer,
      payload: {
        mediaType: options.mediaType || [MEDIA_TYPE.AUDIO],
        displayName: options.displayName,
        groupCall: options.groupCall || false,
        bundleId: options.bundleId || null,  // For GUMBA private calls
      },
    });
  }

  /**
   * Create an SDP offer signal
   */
  static sdpOffer(options) {
    return new VaniSignal({
      type: VANI_CONFIG.messageTypes.SDP_OFFER,
      callId: options.callId,
      fromPeer: options.fromPeer,
      toPeer: options.toPeer,
      payload: {
        sdp: options.sdp,
      },
    });
  }

  /**
   * Create an SDP answer signal
   */
  static sdpAnswer(options) {
    return new VaniSignal({
      type: VANI_CONFIG.messageTypes.SDP_ANSWER,
      callId: options.callId,
      fromPeer: options.fromPeer,
      toPeer: options.toPeer,
      payload: {
        sdp: options.sdp,
      },
    });
  }

  /**
   * Create an ICE candidate signal
   */
  static iceCandidate(options) {
    return new VaniSignal({
      type: VANI_CONFIG.messageTypes.ICE_CANDIDATE,
      callId: options.callId,
      fromPeer: options.fromPeer,
      toPeer: options.toPeer,
      payload: {
        candidate: options.candidate,
        sdpMid: options.sdpMid,
        sdpMLineIndex: options.sdpMLineIndex,
      },
    });
  }

  /**
   * Create call answer signal
   */
  static answer(options) {
    return new VaniSignal({
      type: VANI_CONFIG.messageTypes.CALL_ANSWER,
      callId: options.callId,
      fromPeer: options.fromPeer,
      toPeer: options.toPeer,
      payload: {
        displayName: options.displayName,
        mediaType: options.mediaType,
      },
    });
  }

  /**
   * Create call reject signal
   */
  static reject(options) {
    return new VaniSignal({
      type: VANI_CONFIG.messageTypes.CALL_REJECT,
      callId: options.callId,
      fromPeer: options.fromPeer,
      toPeer: options.toPeer,
      payload: {
        reason: options.reason || CALL_END_REASON.REJECTED,
      },
    });
  }

  /**
   * Create call end signal
   */
  static end(options) {
    return new VaniSignal({
      type: VANI_CONFIG.messageTypes.CALL_END,
      callId: options.callId,
      fromPeer: options.fromPeer,
      toPeer: options.toPeer,
      payload: {
        reason: options.reason || CALL_END_REASON.NORMAL,
      },
    });
  }

  validate() {
    const errors = [];
    if (!this.type) errors.push('type is required');
    if (!this.callId) errors.push('callId is required');
    if (!this.fromPeer) errors.push('fromPeer is required');
    if (!Object.values(VANI_CONFIG.messageTypes).includes(this.type)) {
      errors.push('invalid message type');
    }
    return { valid: errors.length === 0, errors };
  }

  toJSON() {
    return {
      id: this.id,
      type: this.type,
      callId: this.callId,
      fromPeer: this.fromPeer,
      toPeer: this.toPeer,
      timestamp: this.timestamp,
      payload: this.payload,
    };
  }

  static fromJSON(json) {
    return new VaniSignal(json);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VANI CALL - Individual call session
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * VaniCall - Manages a single call session
 * 
 * Handles the full call lifecycle including WebRTC setup.
 * Works in both browser and Node.js (Node requires wrtc package).
 */
export class VaniCall {
  constructor(options = {}) {
    this.id = options.id || VaniCall.generateId();
    this.localPeerId = options.localPeerId;
    this.state = CALL_STATE.IDLE;
    this.isInitiator = options.isInitiator || false;
    this.isGroupCall = options.isGroupCall || false;
    this.bundleId = options.bundleId || null;  // GUMBA bundle for private calls
    
    // Media settings
    this.mediaType = options.mediaType || [MEDIA_TYPE.AUDIO];
    this.constraints = options.constraints || VANI_CONFIG.defaultConstraints;
    this.iceServers = options.iceServers || VANI_CONFIG.iceServers;
    
    // Participants
    this.participants = new Map(); // peerId -> VaniParticipant
    
    // WebRTC connections
    this.peerConnections = new Map(); // peerId -> RTCPeerConnection
    this.localStream = null;
    this.remoteStreams = new Map(); // peerId -> MediaStream
    
    // Pending ICE candidates (before remote description set)
    this.pendingCandidates = new Map(); // peerId -> []
    
    // Timers
    this._ringTimeout = null;
    this._reconnectTimeout = null;
    
    // Callbacks
    this.onStateChange = options.onStateChange || (() => {});
    this.onRemoteStream = options.onRemoteStream || (() => {});
    this.onParticipantJoin = options.onParticipantJoin || (() => {});
    this.onParticipantLeave = options.onParticipantLeave || (() => {});
    this.onSignal = options.onSignal || (() => {});  // Send signal via mesh
    this.onError = options.onError || (() => {});
    
    // Timestamps
    this.createdAt = Date.now();
    this.connectedAt = null;
    this.endedAt = null;
    this.endReason = null;
  }

  static generateId() {
    return 'call-' + bytesToHex(randomBytes(8));
  }

  /**
   * Get RTCPeerConnection (browser or node-wrtc)
   */
  _getRTCPeerConnection() {
    if (typeof RTCPeerConnection !== 'undefined') {
      return RTCPeerConnection;
    }
    // For Node.js, user must provide wrtc
    throw new Error('RTCPeerConnection not available. In Node.js, pass wrtc via options.');
  }

  /**
   * Set call state and notify
   */
  _setState(newState, reason = null) {
    const oldState = this.state;
    this.state = newState;
    
    if (newState === CALL_STATE.CONNECTED && !this.connectedAt) {
      this.connectedAt = Date.now();
    }
    if (newState === CALL_STATE.ENDED || newState === CALL_STATE.FAILED) {
      this.endedAt = Date.now();
      this.endReason = reason;
      this._clearTimers();
    }
    
    this.onStateChange(newState, oldState, reason);
  }

  /**
   * Clear all timers
   */
  _clearTimers() {
    if (this._ringTimeout) {
      clearTimeout(this._ringTimeout);
      this._ringTimeout = null;
    }
    if (this._reconnectTimeout) {
      clearTimeout(this._reconnectTimeout);
      this._reconnectTimeout = null;
    }
  }

  /**
   * Create peer connection for a remote peer
   */
  _createPeerConnection(remotePeerId) {
    const RTCPeerConnectionClass = this._getRTCPeerConnection();
    
    const pc = new RTCPeerConnectionClass({
      iceServers: this.iceServers,
    });

    // Handle ICE candidates
    pc.onicecandidate = (event) => {
      if (event.candidate) {
        const signal = VaniSignal.iceCandidate({
          callId: this.id,
          fromPeer: this.localPeerId,
          toPeer: remotePeerId,
          candidate: event.candidate.candidate,
          sdpMid: event.candidate.sdpMid,
          sdpMLineIndex: event.candidate.sdpMLineIndex,
        });
        this.onSignal(signal);
      }
    };

    // Handle connection state changes
    pc.onconnectionstatechange = () => {
      const participant = this.participants.get(remotePeerId);
      if (participant) {
        participant.connectionState = pc.connectionState;
      }
      
      this._updateCallState();
    };

    // Handle ICE connection state
    pc.oniceconnectionstatechange = () => {
      const participant = this.participants.get(remotePeerId);
      if (participant) {
        participant.iceConnectionState = pc.iceConnectionState;
      }
      
      if (pc.iceConnectionState === 'failed') {
        this._handleConnectionFailure(remotePeerId);
      }
    };

    // Handle remote tracks
    pc.ontrack = (event) => {
      let stream = this.remoteStreams.get(remotePeerId);
      if (!stream) {
        stream = new MediaStream();
        this.remoteStreams.set(remotePeerId, stream);
      }
      stream.addTrack(event.track);
      
      const participant = this.participants.get(remotePeerId);
      if (participant) {
        participant.remoteStream = stream;
      }
      
      this.onRemoteStream(remotePeerId, stream, event.track);
    };

    this.peerConnections.set(remotePeerId, pc);
    return pc;
  }

  /**
   * Update overall call state based on connections
   */
  _updateCallState() {
    if (this.state === CALL_STATE.ENDED || this.state === CALL_STATE.FAILED) {
      return;
    }

    const connections = Array.from(this.peerConnections.values());
    
    if (connections.length === 0) {
      return;
    }

    // Check if all connected
    const allConnected = connections.every(pc => pc.connectionState === 'connected');
    if (allConnected && this.state !== CALL_STATE.CONNECTED) {
      this._setState(CALL_STATE.CONNECTED);
      return;
    }

    // Check if any connecting
    const anyConnecting = connections.some(pc => 
      ['new', 'connecting', 'checking'].includes(pc.connectionState) ||
      ['new', 'checking'].includes(pc.iceConnectionState)
    );
    if (anyConnecting && this.state === CALL_STATE.RINGING) {
      this._setState(CALL_STATE.CONNECTING);
    }
  }

  /**
   * Handle connection failure for a peer
   */
  _handleConnectionFailure(peerId) {
    if (this.isGroupCall && this.peerConnections.size > 1) {
      // In group call, just remove the failed peer
      this.removeParticipant(peerId, CALL_END_REASON.FAILED);
    } else {
      // In 1:1 call, end the call
      this._setState(CALL_STATE.FAILED, CALL_END_REASON.FAILED);
      this.end(CALL_END_REASON.FAILED);
    }
  }

  /**
   * Get local media stream
   */
  async getLocalStream() {
    if (this.localStream) {
      return this.localStream;
    }

    // Build constraints based on media type
    const mediaConstraints = {
      audio: this.mediaType.includes(MEDIA_TYPE.AUDIO) ? this.constraints.audio : false,
      video: this.mediaType.includes(MEDIA_TYPE.VIDEO) ? this.constraints.video : false,
    };

    try {
      // navigator.mediaDevices is browser API
      if (typeof navigator !== 'undefined' && navigator.mediaDevices) {
        this.localStream = await navigator.mediaDevices.getUserMedia(mediaConstraints);
      } else {
        // For Node.js testing, create mock stream
        this.localStream = this._createMockStream();
      }
      return this.localStream;
    } catch (error) {
      this.onError('MEDIA_ACCESS_DENIED', error);
      throw error;
    }
  }

  /**
   * Create mock stream for testing
   */
  _createMockStream() {
    // Return an object that mimics MediaStream for testing
    return {
      id: 'mock-stream-' + Date.now(),
      active: true,
      getTracks: () => [],
      getAudioTracks: () => [],
      getVideoTracks: () => [],
      addTrack: () => {},
      removeTrack: () => {},
    };
  }

  /**
   * Initiate a call to one or more peers
   */
  async initiate(targetPeerIds) {
    if (this.state !== CALL_STATE.IDLE) {
      throw new Error('Call already in progress');
    }

    this.isInitiator = true;
    this._setState(CALL_STATE.INITIATING);

    // Get local media
    const stream = await this.getLocalStream();

    // Create participants
    const peerIds = Array.isArray(targetPeerIds) ? targetPeerIds : [targetPeerIds];
    
    for (const peerId of peerIds) {
      const participant = new VaniParticipant({
        peerId,
      });
      this.participants.set(peerId, participant);

      // Send call offer
      const offer = VaniSignal.offer({
        callId: this.id,
        fromPeer: this.localPeerId,
        toPeer: peerId,
        mediaType: this.mediaType,
        groupCall: peerIds.length > 1,
        bundleId: this.bundleId,
      });
      this.onSignal(offer);
    }

    this._setState(CALL_STATE.RINGING);

    // Set ring timeout
    this._ringTimeout = setTimeout(() => {
      if (this.state === CALL_STATE.RINGING) {
        this._setState(CALL_STATE.ENDED, CALL_END_REASON.TIMEOUT);
        this.end(CALL_END_REASON.TIMEOUT);
      }
    }, VANI_CONFIG.callTimeout);

    return this;
  }

  /**
   * Accept an incoming call
   */
  async accept(callerPeerId) {
    if (this.state !== CALL_STATE.INCOMING) {
      throw new Error('No incoming call to accept');
    }

    // Get local media
    const stream = await this.getLocalStream();

    // Create peer connection
    const pc = this._createPeerConnection(callerPeerId);

    // Add local tracks
    if (stream && stream.getTracks) {
      for (const track of stream.getTracks()) {
        pc.addTrack(track, stream);
      }
    }

    // Send answer signal
    const answer = VaniSignal.answer({
      callId: this.id,
      fromPeer: this.localPeerId,
      toPeer: callerPeerId,
      mediaType: this.mediaType,
    });
    this.onSignal(answer);

    this._setState(CALL_STATE.CONNECTING);
    
    return this;
  }

  /**
   * Reject an incoming call
   */
  reject(reason = CALL_END_REASON.REJECTED) {
    if (this.state !== CALL_STATE.INCOMING) {
      return;
    }

    for (const peerId of this.participants.keys()) {
      const signal = VaniSignal.reject({
        callId: this.id,
        fromPeer: this.localPeerId,
        toPeer: peerId,
        reason,
      });
      this.onSignal(signal);
    }

    this._setState(CALL_STATE.ENDED, reason);
    this.cleanup();
  }

  /**
   * End the call
   */
  end(reason = CALL_END_REASON.NORMAL) {
    if (this.state === CALL_STATE.ENDED) {
      return;
    }

    // Notify all participants
    for (const peerId of this.participants.keys()) {
      const signal = VaniSignal.end({
        callId: this.id,
        fromPeer: this.localPeerId,
        toPeer: peerId,
        reason,
      });
      this.onSignal(signal);
    }

    this._setState(CALL_STATE.ENDED, reason);
    this.cleanup();
  }

  /**
   * Handle incoming signaling message
   */
  async handleSignal(signal) {
    if (signal.callId !== this.id) {
      return;
    }

    const fromPeer = signal.fromPeer;

    switch (signal.type) {
      case VANI_CONFIG.messageTypes.CALL_OFFER:
        await this._handleCallOffer(signal);
        break;

      case VANI_CONFIG.messageTypes.CALL_ANSWER:
        await this._handleCallAnswer(signal);
        break;

      case VANI_CONFIG.messageTypes.CALL_REJECT:
        this._handleCallReject(signal);
        break;

      case VANI_CONFIG.messageTypes.CALL_END:
        this._handleCallEnd(signal);
        break;

      case VANI_CONFIG.messageTypes.SDP_OFFER:
        await this._handleSdpOffer(signal);
        break;

      case VANI_CONFIG.messageTypes.SDP_ANSWER:
        await this._handleSdpAnswer(signal);
        break;

      case VANI_CONFIG.messageTypes.ICE_CANDIDATE:
        await this._handleIceCandidate(signal);
        break;

      case VANI_CONFIG.messageTypes.MUTE_AUDIO:
      case VANI_CONFIG.messageTypes.MUTE_VIDEO:
        this._handleMuteEvent(signal);
        break;
    }
  }

  async _handleCallOffer(signal) {
    if (this.state !== CALL_STATE.IDLE) {
      // Already in a call, send busy
      const busy = new VaniSignal({
        type: VANI_CONFIG.messageTypes.CALL_BUSY,
        callId: signal.callId,
        fromPeer: this.localPeerId,
        toPeer: signal.fromPeer,
      });
      this.onSignal(busy);
      return;
    }

    this.isInitiator = false;
    this.mediaType = signal.payload.mediaType || [MEDIA_TYPE.AUDIO];
    this.isGroupCall = signal.payload.groupCall || false;
    this.bundleId = signal.payload.bundleId;

    // Add caller as participant
    const participant = new VaniParticipant({
      peerId: signal.fromPeer,
      displayName: signal.payload.displayName,
    });
    this.participants.set(signal.fromPeer, participant);

    this._setState(CALL_STATE.INCOMING);
  }

  async _handleCallAnswer(signal) {
    if (this.state !== CALL_STATE.RINGING) {
      return;
    }

    const remotePeerId = signal.fromPeer;
    const participant = this.participants.get(remotePeerId);
    if (participant) {
      participant.displayName = signal.payload.displayName || participant.displayName;
    }

    // Create peer connection and start negotiation
    const pc = this._createPeerConnection(remotePeerId);

    // Add local tracks
    const stream = this.localStream;
    if (stream && stream.getTracks) {
      for (const track of stream.getTracks()) {
        pc.addTrack(track, stream);
      }
    }

    this._setState(CALL_STATE.CONNECTING);

    // Create and send SDP offer
    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      const sdpSignal = VaniSignal.sdpOffer({
        callId: this.id,
        fromPeer: this.localPeerId,
        toPeer: remotePeerId,
        sdp: offer.sdp,
      });
      this.onSignal(sdpSignal);
    } catch (error) {
      this.onError('SDP_CREATE_FAILED', error);
    }
  }

  _handleCallReject(signal) {
    this.removeParticipant(signal.fromPeer, signal.payload.reason);

    if (this.participants.size === 0) {
      this._setState(CALL_STATE.ENDED, signal.payload.reason);
      this.cleanup();
    }
  }

  _handleCallEnd(signal) {
    if (this.isGroupCall) {
      this.removeParticipant(signal.fromPeer, signal.payload.reason);
      if (this.participants.size === 0) {
        this._setState(CALL_STATE.ENDED, signal.payload.reason);
        this.cleanup();
      }
    } else {
      this._setState(CALL_STATE.ENDED, signal.payload.reason);
      this.cleanup();
    }
  }

  async _handleSdpOffer(signal) {
    const remotePeerId = signal.fromPeer;
    
    let pc = this.peerConnections.get(remotePeerId);
    if (!pc) {
      pc = this._createPeerConnection(remotePeerId);
      
      // Add local tracks
      const stream = this.localStream || await this.getLocalStream();
      if (stream && stream.getTracks) {
        for (const track of stream.getTracks()) {
          pc.addTrack(track, stream);
        }
      }
    }

    try {
      await pc.setRemoteDescription({
        type: 'offer',
        sdp: signal.payload.sdp,
      });

      // Process pending ICE candidates
      await this._processPendingCandidates(remotePeerId);

      // Create and send answer
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);

      const sdpSignal = VaniSignal.sdpAnswer({
        callId: this.id,
        fromPeer: this.localPeerId,
        toPeer: remotePeerId,
        sdp: answer.sdp,
      });
      this.onSignal(sdpSignal);
    } catch (error) {
      this.onError('SDP_NEGOTIATION_FAILED', error);
    }
  }

  async _handleSdpAnswer(signal) {
    const remotePeerId = signal.fromPeer;
    const pc = this.peerConnections.get(remotePeerId);
    
    if (!pc) {
      return;
    }

    try {
      await pc.setRemoteDescription({
        type: 'answer',
        sdp: signal.payload.sdp,
      });

      // Process pending ICE candidates
      await this._processPendingCandidates(remotePeerId);
    } catch (error) {
      this.onError('SDP_ANSWER_FAILED', error);
    }
  }

  async _handleIceCandidate(signal) {
    const remotePeerId = signal.fromPeer;
    const pc = this.peerConnections.get(remotePeerId);

    const candidate = {
      candidate: signal.payload.candidate,
      sdpMid: signal.payload.sdpMid,
      sdpMLineIndex: signal.payload.sdpMLineIndex,
    };

    if (!pc || !pc.remoteDescription) {
      // Queue candidate until remote description is set
      if (!this.pendingCandidates.has(remotePeerId)) {
        this.pendingCandidates.set(remotePeerId, []);
      }
      this.pendingCandidates.get(remotePeerId).push(candidate);
      return;
    }

    try {
      await pc.addIceCandidate(candidate);
    } catch (error) {
      // Ignore candidate errors
    }
  }

  async _processPendingCandidates(remotePeerId) {
    const candidates = this.pendingCandidates.get(remotePeerId);
    if (!candidates) return;

    const pc = this.peerConnections.get(remotePeerId);
    if (!pc) return;

    for (const candidate of candidates) {
      try {
        await pc.addIceCandidate(candidate);
      } catch (error) {
        // Ignore
      }
    }

    this.pendingCandidates.delete(remotePeerId);
  }

  _handleMuteEvent(signal) {
    const participant = this.participants.get(signal.fromPeer);
    if (!participant) return;

    if (signal.type === VANI_CONFIG.messageTypes.MUTE_AUDIO) {
      participant.audioEnabled = !signal.payload.muted;
    } else if (signal.type === VANI_CONFIG.messageTypes.MUTE_VIDEO) {
      participant.videoEnabled = !signal.payload.muted;
    }
  }

  /**
   * Mute/unmute local audio
   */
  setAudioEnabled(enabled) {
    if (this.localStream && this.localStream.getAudioTracks) {
      for (const track of this.localStream.getAudioTracks()) {
        track.enabled = enabled;
      }
    }

    // Notify peers
    const signal = new VaniSignal({
      type: VANI_CONFIG.messageTypes.MUTE_AUDIO,
      callId: this.id,
      fromPeer: this.localPeerId,
      toPeer: null,
      payload: { muted: !enabled },
    });
    this.onSignal(signal);
  }

  /**
   * Mute/unmute local video
   */
  setVideoEnabled(enabled) {
    if (this.localStream && this.localStream.getVideoTracks) {
      for (const track of this.localStream.getVideoTracks()) {
        track.enabled = enabled;
      }
    }

    const signal = new VaniSignal({
      type: VANI_CONFIG.messageTypes.MUTE_VIDEO,
      callId: this.id,
      fromPeer: this.localPeerId,
      toPeer: null,
      payload: { muted: !enabled },
    });
    this.onSignal(signal);
  }

  /**
   * Add a participant to group call
   */
  addParticipant(peerId, displayName) {
    if (!this.isGroupCall) {
      throw new Error('Cannot add participant to 1:1 call');
    }

    const participant = new VaniParticipant({
      peerId,
      displayName,
    });
    this.participants.set(peerId, participant);
    this.onParticipantJoin(participant);

    return participant;
  }

  /**
   * Remove a participant
   */
  removeParticipant(peerId, reason = CALL_END_REASON.PARTICIPANT_LEFT) {
    const participant = this.participants.get(peerId);
    if (!participant) return;

    // Close peer connection
    const pc = this.peerConnections.get(peerId);
    if (pc) {
      pc.close();
      this.peerConnections.delete(peerId);
    }

    // Remove remote stream
    this.remoteStreams.delete(peerId);
    this.pendingCandidates.delete(peerId);
    this.participants.delete(peerId);

    this.onParticipantLeave(participant, reason);
  }

  /**
   * Clean up all resources
   */
  cleanup() {
    this._clearTimers();

    // Close all peer connections
    for (const pc of this.peerConnections.values()) {
      pc.close();
    }
    this.peerConnections.clear();

    // Stop local stream
    if (this.localStream && this.localStream.getTracks) {
      for (const track of this.localStream.getTracks()) {
        track.stop();
      }
    }
    this.localStream = null;

    // Clear remote streams
    this.remoteStreams.clear();
    this.pendingCandidates.clear();
  }

  /**
   * Get call duration in ms
   */
  getDuration() {
    if (!this.connectedAt) return 0;
    const end = this.endedAt || Date.now();
    return end - this.connectedAt;
  }

  /**
   * Get call info
   */
  toJSON() {
    return {
      id: this.id,
      localPeerId: this.localPeerId,
      state: this.state,
      isInitiator: this.isInitiator,
      isGroupCall: this.isGroupCall,
      bundleId: this.bundleId,
      mediaType: this.mediaType,
      participants: Array.from(this.participants.values()).map(p => p.toJSON()),
      createdAt: this.createdAt,
      connectedAt: this.connectedAt,
      endedAt: this.endedAt,
      endReason: this.endReason,
      duration: this.getDuration(),
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VANI HUB - Multi-call manager
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * VaniHub - Manages multiple concurrent calls
 */
export class VaniHub {
  constructor(options = {}) {
    this.localPeerId = options.localPeerId;
    this.iceServers = options.iceServers || VANI_CONFIG.iceServers;
    this.calls = new Map(); // callId -> VaniCall
    this.activeCallId = null;
    
    this.eventHandlers = new Map();
    this.onSignal = options.onSignal || (() => {});
  }

  /**
   * Start a new call
   */
  async startCall(options) {
    const call = new VaniCall({
      localPeerId: this.localPeerId,
      iceServers: this.iceServers,
      mediaType: options.mediaType || [MEDIA_TYPE.AUDIO],
      isGroupCall: options.isGroupCall || false,
      bundleId: options.bundleId,
      onSignal: (signal) => {
        this.onSignal(signal);
        this._emit('signal', signal);
      },
      onStateChange: (state, old, reason) => {
        this._emit('stateChange', { callId: call.id, state, oldState: old, reason });
        if (state === CALL_STATE.ENDED || state === CALL_STATE.FAILED) {
          this.calls.delete(call.id);
          if (this.activeCallId === call.id) {
            this.activeCallId = null;
          }
        }
      },
      onRemoteStream: (peerId, stream, track) => {
        this._emit('remoteStream', { callId: call.id, peerId, stream, track });
      },
      onParticipantJoin: (participant) => {
        this._emit('participantJoin', { callId: call.id, participant });
      },
      onParticipantLeave: (participant, reason) => {
        this._emit('participantLeave', { callId: call.id, participant, reason });
      },
      onError: (code, error) => {
        this._emit('error', { callId: call.id, code, error });
      },
    });

    this.calls.set(call.id, call);
    this.activeCallId = call.id;

    const targets = options.targetPeerIds;
    await call.initiate(targets);

    return call;
  }

  /**
   * Handle incoming signal
   */
  async handleSignal(signal) {
    const callId = signal.callId;
    
    // Check if this is for an existing call
    let call = this.calls.get(callId);
    
    // If it's a new call offer, create the call
    if (!call && signal.type === VANI_CONFIG.messageTypes.CALL_OFFER) {
      call = new VaniCall({
        id: callId,
        localPeerId: this.localPeerId,
        iceServers: this.iceServers,
        onSignal: (sig) => {
          this.onSignal(sig);
          this._emit('signal', sig);
        },
        onStateChange: (state, old, reason) => {
          this._emit('stateChange', { callId: call.id, state, oldState: old, reason });
          if (state === CALL_STATE.ENDED || state === CALL_STATE.FAILED) {
            this.calls.delete(call.id);
          }
        },
        onRemoteStream: (peerId, stream, track) => {
          this._emit('remoteStream', { callId: call.id, peerId, stream, track });
        },
        onParticipantJoin: (participant) => {
          this._emit('participantJoin', { callId: call.id, participant });
        },
        onParticipantLeave: (participant, reason) => {
          this._emit('participantLeave', { callId: call.id, participant, reason });
        },
        onError: (code, error) => {
          this._emit('error', { callId: call.id, code, error });
        },
      });
      
      this.calls.set(callId, call);
      this._emit('incomingCall', { call, signal });
    }
    
    if (call) {
      await call.handleSignal(signal);
    }
  }

  /**
   * Get call by ID
   */
  getCall(callId) {
    return this.calls.get(callId) || null;
  }

  /**
   * Get active call
   */
  getActiveCall() {
    return this.activeCallId ? this.calls.get(this.activeCallId) : null;
  }

  /**
   * Accept incoming call
   */
  async acceptCall(callId) {
    const call = this.calls.get(callId);
    if (!call) {
      throw new Error('Call not found');
    }
    
    // End any active call first
    if (this.activeCallId && this.activeCallId !== callId) {
      const activeCall = this.calls.get(this.activeCallId);
      if (activeCall) {
        activeCall.end(CALL_END_REASON.NORMAL);
      }
    }
    
    this.activeCallId = callId;
    
    // Get the caller's peer ID from participants
    const callerPeerId = Array.from(call.participants.keys())[0];
    await call.accept(callerPeerId);
    
    return call;
  }

  /**
   * Reject incoming call
   */
  rejectCall(callId, reason = CALL_END_REASON.REJECTED) {
    const call = this.calls.get(callId);
    if (call) {
      call.reject(reason);
      this.calls.delete(callId);
    }
  }

  /**
   * End a call
   */
  endCall(callId, reason = CALL_END_REASON.NORMAL) {
    const call = this.calls.get(callId);
    if (call) {
      call.end(reason);
    }
  }

  /**
   * Register event handler
   */
  on(eventType, handler) {
    if (!this.eventHandlers.has(eventType)) {
      this.eventHandlers.set(eventType, []);
    }
    this.eventHandlers.get(eventType).push(handler);
  }

  /**
   * Remove event handler
   */
  off(eventType, handler) {
    const handlers = this.eventHandlers.get(eventType);
    if (handlers) {
      const idx = handlers.indexOf(handler);
      if (idx >= 0) handlers.splice(idx, 1);
    }
  }

  /**
   * Emit event
   */
  _emit(eventType, data) {
    const handlers = this.eventHandlers.get(eventType) || [];
    for (const handler of handlers) {
      try {
        handler(data);
      } catch (err) {
        console.error('Vani handler error:', err);
      }
    }
  }

  /**
   * Get hub stats
   */
  getStats() {
    return {
      localPeerId: this.localPeerId,
      activeCallId: this.activeCallId,
      callCount: this.calls.size,
      calls: Array.from(this.calls.values()).map(c => ({
        id: c.id,
        state: c.state,
        participants: c.participants.size,
        duration: c.getDuration(),
      })),
    };
  }

  /**
   * Clean up all calls
   */
  cleanup() {
    for (const call of this.calls.values()) {
      call.end(CALL_END_REASON.NORMAL);
      call.cleanup();
    }
    this.calls.clear();
    this.activeCallId = null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export default {
  VANI_CONFIG,
  CALL_STATE,
  CALL_END_REASON,
  MEDIA_TYPE,
  VaniParticipant,
  VaniSignal,
  VaniCall,
  VaniHub,
};
