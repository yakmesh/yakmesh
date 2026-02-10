/**
 * VANI Tests - Voice And Networked Interaction
 * 
 * Tests for WebRTC signaling and call management.
 * Uses mocks since RTCPeerConnection isn't available in Node.js.
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  VANI_CONFIG,
  CALL_STATE,
  CALL_END_REASON,
  MEDIA_TYPE,
  VaniParticipant,
  VaniSignal,
  VaniCall,
  VaniHub,
} from '../vani.js';

// ═══════════════════════════════════════════════════════════════════════════════
// MOCK WEBRTC
// ═══════════════════════════════════════════════════════════════════════════════

class MockRTCPeerConnection {
  constructor(config) {
    this.config = config;
    this.localDescription = null;
    this.remoteDescription = null;
    this.connectionState = 'new';
    this.iceConnectionState = 'new';
    this.onicecandidate = null;
    this.onconnectionstatechange = null;
    this.oniceconnectionstatechange = null;
    this.ontrack = null;
    this._tracks = [];
    this._closed = false;
  }

  async createOffer() {
    return { type: 'offer', sdp: 'mock-offer-sdp-' + Date.now() };
  }

  async createAnswer() {
    return { type: 'answer', sdp: 'mock-answer-sdp-' + Date.now() };
  }

  async setLocalDescription(desc) {
    this.localDescription = desc;
  }

  async setRemoteDescription(desc) {
    this.remoteDescription = desc;
  }

  async addIceCandidate(candidate) {
    // Mock candidate addition
  }

  addTrack(track, stream) {
    this._tracks.push({ track, stream });
  }

  close() {
    this._closed = true;
    this.connectionState = 'closed';
  }

  // Simulate connection success
  simulateConnected() {
    this.connectionState = 'connected';
    this.iceConnectionState = 'connected';
    if (this.onconnectionstatechange) this.onconnectionstatechange();
    if (this.oniceconnectionstatechange) this.oniceconnectionstatechange();
  }

  // Simulate ICE candidate
  simulateIceCandidate(candidate) {
    if (this.onicecandidate) {
      this.onicecandidate({ candidate });
    }
  }

  // Simulate remote track
  simulateRemoteTrack(track) {
    if (this.ontrack) {
      this.ontrack({ track });
    }
  }
}

// Inject mock into global
globalThis.RTCPeerConnection = MockRTCPeerConnection;

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('VANI Configuration', () => {
  test('VANI_CONFIG is frozen', () => {
    expect(Object.isFrozen(VANI_CONFIG)).toBe(true);
  });

  test('call timeout is 30 seconds', () => {
    expect(VANI_CONFIG.callTimeout).toBe(30000);
  });

  test('max participants default is 10', () => {
    expect(VANI_CONFIG.maxParticipants).toBe(10);
  });

  test('iceServers is configurable (empty by default)', () => {
    // ETHOS: No external dependencies by default, use mesh relay
    expect(Array.isArray(VANI_CONFIG.iceServers)).toBe(true);
    // Can be configured if needed for hybrid deployments
  });

  test('has all message types defined', () => {
    const types = VANI_CONFIG.messageTypes;
    expect(types.CALL_OFFER).toBe('vani:call:offer');
    expect(types.CALL_ANSWER).toBe('vani:call:answer');
    expect(types.CALL_REJECT).toBe('vani:call:reject');
    expect(types.CALL_END).toBe('vani:call:end');
    expect(types.SDP_OFFER).toBe('vani:sdp:offer');
    expect(types.SDP_ANSWER).toBe('vani:sdp:answer');
    expect(types.ICE_CANDIDATE).toBe('vani:ice:candidate');
    expect(types.MUTE_AUDIO).toBe('vani:mute:audio');
    expect(types.MUTE_VIDEO).toBe('vani:mute:video');
  });

  test('default media constraints include echo cancellation', () => {
    expect(VANI_CONFIG.defaultConstraints.audio.echoCancellation).toBe(true);
    expect(VANI_CONFIG.defaultConstraints.audio.noiseSuppression).toBe(true);
  });
});

describe('Call States', () => {
  test('CALL_STATE is frozen', () => {
    expect(Object.isFrozen(CALL_STATE)).toBe(true);
  });

  test('has all required states', () => {
    expect(CALL_STATE.IDLE).toBe('idle');
    expect(CALL_STATE.INITIATING).toBe('initiating');
    expect(CALL_STATE.RINGING).toBe('ringing');
    expect(CALL_STATE.INCOMING).toBe('incoming');
    expect(CALL_STATE.CONNECTING).toBe('connecting');
    expect(CALL_STATE.CONNECTED).toBe('connected');
    expect(CALL_STATE.RECONNECTING).toBe('reconnecting');
    expect(CALL_STATE.ENDED).toBe('ended');
    expect(CALL_STATE.FAILED).toBe('failed');
  });
});

describe('Call End Reasons', () => {
  test('CALL_END_REASON is frozen', () => {
    expect(Object.isFrozen(CALL_END_REASON)).toBe(true);
  });

  test('has all required reasons', () => {
    expect(CALL_END_REASON.NORMAL).toBe('normal');
    expect(CALL_END_REASON.REJECTED).toBe('rejected');
    expect(CALL_END_REASON.BUSY).toBe('busy');
    expect(CALL_END_REASON.TIMEOUT).toBe('timeout');
    expect(CALL_END_REASON.FAILED).toBe('failed');
    expect(CALL_END_REASON.NETWORK_ERROR).toBe('network');
    expect(CALL_END_REASON.PARTICIPANT_LEFT).toBe('left');
  });
});

describe('Media Types', () => {
  test('MEDIA_TYPE is frozen', () => {
    expect(Object.isFrozen(MEDIA_TYPE)).toBe(true);
  });

  test('has audio, video, screen', () => {
    expect(MEDIA_TYPE.AUDIO).toBe('audio');
    expect(MEDIA_TYPE.VIDEO).toBe('video');
    expect(MEDIA_TYPE.SCREEN).toBe('screen');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// VANI CONFIG ETHOS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('VANI_CONFIG Ethos', () => {
  test('iceServers is empty by default (no external dependencies)', () => {
    // CRITICAL: Yakmesh ethos - no hardcoded external services
    expect(VANI_CONFIG.iceServers).toEqual([]);
  });
  
  test('mesh relay is enabled by default', () => {
    expect(VANI_CONFIG.meshRelayEnabled).toBe(true);
  });
  
  test('mesh relay timeout is reasonable', () => {
    expect(VANI_CONFIG.meshRelayTimeout).toBe(5000);
  });
  
  test('config does not contain google.com references', () => {
    const configString = JSON.stringify(VANI_CONFIG);
    expect(configString).not.toContain('google.com');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// VANI PARTICIPANT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('VaniParticipant', () => {
  test('creates with generated ID', () => {
    const p = new VaniParticipant({ peerId: 'peer-123' });
    expect(p.id).toMatch(/^p-[a-f0-9]{16}$/);
    expect(p.peerId).toBe('peer-123');
  });

  test('creates with all options', () => {
    const p = new VaniParticipant({
      id: 'custom-id',
      peerId: 'peer-456',
      displayName: 'Alice',
      audioEnabled: false,
      videoEnabled: true,
      screenSharing: true,
    });

    expect(p.id).toBe('custom-id');
    expect(p.peerId).toBe('peer-456');
    expect(p.displayName).toBe('Alice');
    expect(p.audioEnabled).toBe(false);
    expect(p.videoEnabled).toBe(true);
    expect(p.screenSharing).toBe(true);
  });

  test('defaults audio and video to enabled', () => {
    const p = new VaniParticipant({ peerId: 'peer' });
    expect(p.audioEnabled).toBe(true);
    expect(p.videoEnabled).toBe(true);
    expect(p.screenSharing).toBe(false);
  });

  test('defaults displayName to peerId', () => {
    const p = new VaniParticipant({ peerId: 'peer-xyz' });
    expect(p.displayName).toBe('peer-xyz');
  });

  test('serializes to JSON', () => {
    const p = new VaniParticipant({
      peerId: 'peer-json',
      displayName: 'Bob',
    });
    const json = p.toJSON();

    expect(json.id).toBe(p.id);
    expect(json.peerId).toBe('peer-json');
    expect(json.displayName).toBe('Bob');
    expect(json.joinedAt).toBeDefined();
    expect(json.audioEnabled).toBe(true);
    expect(json.videoEnabled).toBe(true);
    expect(json.connectionState).toBe('new');
  });

  test('deserializes from JSON', () => {
    const original = new VaniParticipant({
      peerId: 'peer-round-trip',
      displayName: 'Charlie',
      audioEnabled: false,
    });
    const json = original.toJSON();
    const restored = VaniParticipant.fromJSON(json);

    expect(restored.id).toBe(original.id);
    expect(restored.peerId).toBe('peer-round-trip');
    expect(restored.displayName).toBe('Charlie');
    expect(restored.audioEnabled).toBe(false);
  });

  test('generateId returns unique IDs', () => {
    const ids = new Set();
    for (let i = 0; i < 100; i++) {
      ids.add(VaniParticipant.generateId());
    }
    expect(ids.size).toBe(100);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// VANI SIGNAL TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('VaniSignal', () => {
  test('creates with generated ID', () => {
    const s = new VaniSignal({
      type: VANI_CONFIG.messageTypes.CALL_OFFER,
      callId: 'call-123',
      fromPeer: 'peer-a',
    });
    expect(s.id).toMatch(/^s-[a-f0-9]{16}$/);
  });

  test('creates call offer signal', () => {
    const s = VaniSignal.offer({
      callId: 'call-1',
      fromPeer: 'alice',
      toPeer: 'bob',
      mediaType: [MEDIA_TYPE.AUDIO, MEDIA_TYPE.VIDEO],
      displayName: 'Alice',
      groupCall: false,
    });

    expect(s.type).toBe(VANI_CONFIG.messageTypes.CALL_OFFER);
    expect(s.callId).toBe('call-1');
    expect(s.fromPeer).toBe('alice');
    expect(s.toPeer).toBe('bob');
    expect(s.payload.mediaType).toContain(MEDIA_TYPE.AUDIO);
    expect(s.payload.mediaType).toContain(MEDIA_TYPE.VIDEO);
    expect(s.payload.displayName).toBe('Alice');
    expect(s.payload.groupCall).toBe(false);
  });

  test('creates SDP offer signal', () => {
    const s = VaniSignal.sdpOffer({
      callId: 'call-2',
      fromPeer: 'alice',
      toPeer: 'bob',
      sdp: 'mock-sdp-offer',
    });

    expect(s.type).toBe(VANI_CONFIG.messageTypes.SDP_OFFER);
    expect(s.payload.sdp).toBe('mock-sdp-offer');
  });

  test('creates SDP answer signal', () => {
    const s = VaniSignal.sdpAnswer({
      callId: 'call-3',
      fromPeer: 'bob',
      toPeer: 'alice',
      sdp: 'mock-sdp-answer',
    });

    expect(s.type).toBe(VANI_CONFIG.messageTypes.SDP_ANSWER);
    expect(s.payload.sdp).toBe('mock-sdp-answer');
  });

  test('creates ICE candidate signal', () => {
    const s = VaniSignal.iceCandidate({
      callId: 'call-4',
      fromPeer: 'alice',
      toPeer: 'bob',
      candidate: 'candidate:1 1 UDP...',
      sdpMid: '0',
      sdpMLineIndex: 0,
    });

    expect(s.type).toBe(VANI_CONFIG.messageTypes.ICE_CANDIDATE);
    expect(s.payload.candidate).toContain('candidate');
    expect(s.payload.sdpMid).toBe('0');
    expect(s.payload.sdpMLineIndex).toBe(0);
  });

  test('creates call answer signal', () => {
    const s = VaniSignal.answer({
      callId: 'call-5',
      fromPeer: 'bob',
      toPeer: 'alice',
      displayName: 'Bob',
      mediaType: [MEDIA_TYPE.AUDIO],
    });

    expect(s.type).toBe(VANI_CONFIG.messageTypes.CALL_ANSWER);
    expect(s.payload.displayName).toBe('Bob');
  });

  test('creates call reject signal', () => {
    const s = VaniSignal.reject({
      callId: 'call-6',
      fromPeer: 'bob',
      toPeer: 'alice',
      reason: CALL_END_REASON.BUSY,
    });

    expect(s.type).toBe(VANI_CONFIG.messageTypes.CALL_REJECT);
    expect(s.payload.reason).toBe(CALL_END_REASON.BUSY);
  });

  test('creates call end signal', () => {
    const s = VaniSignal.end({
      callId: 'call-7',
      fromPeer: 'alice',
      toPeer: 'bob',
      reason: CALL_END_REASON.NORMAL,
    });

    expect(s.type).toBe(VANI_CONFIG.messageTypes.CALL_END);
    expect(s.payload.reason).toBe(CALL_END_REASON.NORMAL);
  });

  test('validates complete signal', () => {
    const s = VaniSignal.offer({
      callId: 'call-valid',
      fromPeer: 'alice',
      toPeer: 'bob',
    });
    const result = s.validate();
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  test('validates missing type', () => {
    const s = new VaniSignal({
      callId: 'call-x',
      fromPeer: 'alice',
    });
    const result = s.validate();
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('type is required');
  });

  test('validates missing callId', () => {
    const s = new VaniSignal({
      type: VANI_CONFIG.messageTypes.CALL_OFFER,
      fromPeer: 'alice',
    });
    const result = s.validate();
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('callId is required');
  });

  test('validates invalid type', () => {
    const s = new VaniSignal({
      type: 'invalid:type',
      callId: 'call-y',
      fromPeer: 'alice',
    });
    const result = s.validate();
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('invalid message type');
  });

  test('serializes to JSON', () => {
    const s = VaniSignal.offer({
      callId: 'call-json',
      fromPeer: 'alice',
      toPeer: 'bob',
    });
    const json = s.toJSON();

    expect(json.id).toBe(s.id);
    expect(json.type).toBe(VANI_CONFIG.messageTypes.CALL_OFFER);
    expect(json.callId).toBe('call-json');
    expect(json.timestamp).toBeDefined();
  });

  test('deserializes from JSON', () => {
    const original = VaniSignal.sdpOffer({
      callId: 'call-rt',
      fromPeer: 'alice',
      toPeer: 'bob',
      sdp: 'test-sdp',
    });
    const restored = VaniSignal.fromJSON(original.toJSON());

    expect(restored.id).toBe(original.id);
    expect(restored.type).toBe(original.type);
    expect(restored.payload.sdp).toBe('test-sdp');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// VANI CALL TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('VaniCall', () => {
  let signalsSent;
  let stateChanges;
  
  beforeEach(() => {
    signalsSent = [];
    stateChanges = [];
  });

  function createTestCall(options = {}) {
    return new VaniCall({
      localPeerId: 'local-peer',
      onSignal: (sig) => signalsSent.push(sig),
      onStateChange: (state, old, reason) => stateChanges.push({ state, old, reason }),
      ...options,
    });
  }

  test('creates with generated ID', () => {
    const call = createTestCall();
    expect(call.id).toMatch(/^call-[a-f0-9]{16}$/);
    expect(call.state).toBe(CALL_STATE.IDLE);
  });

  test('creates with custom options', () => {
    const call = createTestCall({
      id: 'custom-call-id',
      bundleId: 'bundle-123',
      mediaType: [MEDIA_TYPE.AUDIO, MEDIA_TYPE.VIDEO],
    });

    expect(call.id).toBe('custom-call-id');
    expect(call.bundleId).toBe('bundle-123');
    expect(call.mediaType).toContain(MEDIA_TYPE.VIDEO);
  });

  test('defaults to audio only', () => {
    const call = createTestCall();
    expect(call.mediaType).toEqual([MEDIA_TYPE.AUDIO]);
  });

  test('starts in IDLE state', () => {
    const call = createTestCall();
    expect(call.state).toBe(CALL_STATE.IDLE);
    expect(call.isInitiator).toBe(false);
    expect(call.isGroupCall).toBe(false);
  });

  test('initiates call and sends offer', async () => {
    const call = createTestCall();
    await call.initiate('remote-peer');

    expect(call.isInitiator).toBe(true);
    expect(call.state).toBe(CALL_STATE.RINGING);
    expect(call.participants.has('remote-peer')).toBe(true);
    
    // Should have sent call offer
    const offer = signalsSent.find(s => s.type === VANI_CONFIG.messageTypes.CALL_OFFER);
    expect(offer).toBeDefined();
    expect(offer.toPeer).toBe('remote-peer');
  });

  test('initiates group call to multiple peers', async () => {
    const call = createTestCall({
      isGroupCall: true,
    });
    await call.initiate(['peer-1', 'peer-2', 'peer-3']);

    expect(call.participants.size).toBe(3);
    
    const offers = signalsSent.filter(s => s.type === VANI_CONFIG.messageTypes.CALL_OFFER);
    expect(offers.length).toBe(3);
    expect(offers[0].payload.groupCall).toBe(true);
  });

  test('cannot initiate when not idle', async () => {
    const call = createTestCall();
    await call.initiate('peer-1');

    await expect(call.initiate('peer-2')).rejects.toThrow('Call already in progress');
  });

  test('handles incoming call offer', async () => {
    const call = createTestCall();
    
    const offer = VaniSignal.offer({
      callId: call.id,
      fromPeer: 'remote-peer',
      toPeer: call.localPeerId,
      mediaType: [MEDIA_TYPE.AUDIO, MEDIA_TYPE.VIDEO],
      displayName: 'Remote User',
      groupCall: false,
    });

    await call.handleSignal(offer);

    expect(call.state).toBe(CALL_STATE.INCOMING);
    expect(call.isInitiator).toBe(false);
    expect(call.mediaType).toContain(MEDIA_TYPE.VIDEO);
    expect(call.participants.has('remote-peer')).toBe(true);
    expect(call.participants.get('remote-peer').displayName).toBe('Remote User');
  });

  test('accepts incoming call', async () => {
    const call = createTestCall();
    
    // Receive offer
    const offer = VaniSignal.offer({
      callId: call.id,
      fromPeer: 'caller',
      toPeer: 'local-peer',
    });
    await call.handleSignal(offer);

    // Accept
    await call.accept('caller');

    expect(call.state).toBe(CALL_STATE.CONNECTING);
    
    // Should have sent answer
    const answer = signalsSent.find(s => s.type === VANI_CONFIG.messageTypes.CALL_ANSWER);
    expect(answer).toBeDefined();
    expect(answer.toPeer).toBe('caller');
  });

  test('rejects incoming call', async () => {
    const call = createTestCall();
    
    // Receive offer
    const offer = VaniSignal.offer({
      callId: call.id,
      fromPeer: 'caller',
      toPeer: 'local-peer',
    });
    await call.handleSignal(offer);

    // Reject
    call.reject(CALL_END_REASON.BUSY);

    expect(call.state).toBe(CALL_STATE.ENDED);
    expect(call.endReason).toBe(CALL_END_REASON.BUSY);
    
    const reject = signalsSent.find(s => s.type === VANI_CONFIG.messageTypes.CALL_REJECT);
    expect(reject).toBeDefined();
    expect(reject.payload.reason).toBe(CALL_END_REASON.BUSY);
  });

  test('ends call and notifies participant', async () => {
    const call = createTestCall();
    await call.initiate('remote-peer');

    call.end(CALL_END_REASON.NORMAL);

    expect(call.state).toBe(CALL_STATE.ENDED);
    expect(call.endReason).toBe(CALL_END_REASON.NORMAL);
    expect(call.endedAt).toBeDefined();
    
    const endSignal = signalsSent.find(s => s.type === VANI_CONFIG.messageTypes.CALL_END);
    expect(endSignal).toBeDefined();
    expect(endSignal.payload.reason).toBe(CALL_END_REASON.NORMAL);
  });

  test('handles call answer and starts negotiation', async () => {
    const call = createTestCall();
    await call.initiate('remote-peer');

    // Receive answer
    const answer = VaniSignal.answer({
      callId: call.id,
      fromPeer: 'remote-peer',
      toPeer: 'local-peer',
      displayName: 'Remote Name',
    });
    await call.handleSignal(answer);

    expect(call.state).toBe(CALL_STATE.CONNECTING);
    
    // Should have sent SDP offer
    const sdpOffer = signalsSent.find(s => s.type === VANI_CONFIG.messageTypes.SDP_OFFER);
    expect(sdpOffer).toBeDefined();
    expect(sdpOffer.payload.sdp).toBeDefined();
  });

  test('handles SDP offer and sends answer', async () => {
    const call = createTestCall();
    
    // Set up as receiver
    const offer = VaniSignal.offer({ callId: call.id, fromPeer: 'caller', toPeer: 'local-peer' });
    await call.handleSignal(offer);
    await call.accept('caller');

    // Receive SDP offer
    const sdpOffer = VaniSignal.sdpOffer({
      callId: call.id,
      fromPeer: 'caller',
      toPeer: 'local-peer',
      sdp: 'mock-remote-sdp',
    });
    await call.handleSignal(sdpOffer);

    // Should have sent SDP answer
    const sdpAnswer = signalsSent.find(s => s.type === VANI_CONFIG.messageTypes.SDP_ANSWER);
    expect(sdpAnswer).toBeDefined();
    expect(sdpAnswer.payload.sdp).toBeDefined();
  });

  test('handles ICE candidate', async () => {
    const call = createTestCall();
    await call.initiate('remote-peer');

    // Receive answer to create peer connection
    const answer = VaniSignal.answer({ callId: call.id, fromPeer: 'remote-peer', toPeer: 'local-peer' });
    await call.handleSignal(answer);

    // Receive SDP offer (since we're initiator)
    const sdpOffer = VaniSignal.sdpOffer({
      callId: call.id,
      fromPeer: 'remote-peer',
      toPeer: 'local-peer',
      sdp: 'mock-sdp',
    });
    await call.handleSignal(sdpOffer);

    // Now receive ICE candidate
    const ice = VaniSignal.iceCandidate({
      callId: call.id,
      fromPeer: 'remote-peer',
      toPeer: 'local-peer',
      candidate: 'candidate:1 1 UDP...',
      sdpMid: '0',
      sdpMLineIndex: 0,
    });
    await call.handleSignal(ice);

    // ICE candidate should be processed without error
    expect(call.state).not.toBe(CALL_STATE.FAILED);
  });

  test('queues ICE candidates before remote description', async () => {
    const call = createTestCall();
    await call.initiate('remote-peer');

    // Send ICE before SDP - should queue
    const ice = VaniSignal.iceCandidate({
      callId: call.id,
      fromPeer: 'remote-peer',
      toPeer: 'local-peer',
      candidate: 'candidate:early',
      sdpMid: '0',
      sdpMLineIndex: 0,
    });
    await call.handleSignal(ice);

    expect(call.pendingCandidates.has('remote-peer')).toBe(true);
    expect(call.pendingCandidates.get('remote-peer').length).toBe(1);
  });

  test('tracks call duration', async () => {
    const call = createTestCall();
    expect(call.getDuration()).toBe(0);

    // Simulate connected state
    call.connectedAt = Date.now() - 5000;
    expect(call.getDuration()).toBeGreaterThanOrEqual(5000);
  });

  test('serializes to JSON', async () => {
    const call = createTestCall({ bundleId: 'gumba-bundle' });
    await call.initiate('peer-1');

    const json = call.toJSON();

    expect(json.id).toBe(call.id);
    expect(json.localPeerId).toBe('local-peer');
    expect(json.state).toBe(CALL_STATE.RINGING);
    expect(json.bundleId).toBe('gumba-bundle');
    expect(json.participants.length).toBe(1);
    expect(json.createdAt).toBeDefined();
  });

  test('cleans up resources on end', async () => {
    const call = createTestCall();
    await call.initiate('remote-peer');

    // Simulate peer connection
    const answer = VaniSignal.answer({ callId: call.id, fromPeer: 'remote-peer', toPeer: 'local-peer' });
    await call.handleSignal(answer);

    call.end();
    call.cleanup();

    expect(call.peerConnections.size).toBe(0);
    expect(call.remoteStreams.size).toBe(0);
    expect(call.localStream).toBe(null);
  });

  test('sends busy when receiving offer while in call', async () => {
    const call = createTestCall();
    await call.initiate('peer-a');

    // Receive a second call offer for the same call ID while busy
    const offer = VaniSignal.offer({
      callId: call.id,  // Same call ID
      fromPeer: 'peer-b',
      toPeer: 'local-peer',
    });
    await call.handleSignal(offer);

    // Should have sent busy (state is RINGING, not IDLE)
    const busy = signalsSent.find(s => s.type === VANI_CONFIG.messageTypes.CALL_BUSY);
    expect(busy).toBeDefined();
    expect(busy.toPeer).toBe('peer-b');
  });

  test('handles mute audio signal', async () => {
    const call = createTestCall();
    
    // Set up call
    const offer = VaniSignal.offer({ callId: call.id, fromPeer: 'remote', toPeer: 'local-peer' });
    await call.handleSignal(offer);

    // Receive mute signal
    const mute = new VaniSignal({
      type: VANI_CONFIG.messageTypes.MUTE_AUDIO,
      callId: call.id,
      fromPeer: 'remote',
      payload: { muted: true },
    });
    await call.handleSignal(mute);

    const participant = call.participants.get('remote');
    expect(participant.audioEnabled).toBe(false);
  });

  test('handles mute video signal', async () => {
    const call = createTestCall();
    
    const offer = VaniSignal.offer({ callId: call.id, fromPeer: 'remote', toPeer: 'local-peer' });
    await call.handleSignal(offer);

    const mute = new VaniSignal({
      type: VANI_CONFIG.messageTypes.MUTE_VIDEO,
      callId: call.id,
      fromPeer: 'remote',
      payload: { muted: true },
    });
    await call.handleSignal(mute);

    const participant = call.participants.get('remote');
    expect(participant.videoEnabled).toBe(false);
  });

  test('setAudioEnabled sends mute signal', async () => {
    const call = createTestCall();
    await call.initiate('remote');

    call.setAudioEnabled(false);

    const mute = signalsSent.find(s => s.type === VANI_CONFIG.messageTypes.MUTE_AUDIO);
    expect(mute).toBeDefined();
    expect(mute.payload.muted).toBe(true);
  });

  test('setVideoEnabled sends mute signal', async () => {
    const call = createTestCall();
    await call.initiate('remote');

    call.setVideoEnabled(false);

    const mute = signalsSent.find(s => s.type === VANI_CONFIG.messageTypes.MUTE_VIDEO);
    expect(mute).toBeDefined();
    expect(mute.payload.muted).toBe(true);
  });

  test('group call removes participant on end', async () => {
    const call = createTestCall({ isGroupCall: true });
    await call.initiate(['peer-1', 'peer-2']);

    expect(call.participants.size).toBe(2);

    // Simulate peer-1 leaving
    const endSignal = VaniSignal.end({
      callId: call.id,
      fromPeer: 'peer-1',
      toPeer: 'local-peer',
    });
    await call.handleSignal(endSignal);

    expect(call.participants.size).toBe(1);
    expect(call.participants.has('peer-1')).toBe(false);
    expect(call.state).not.toBe(CALL_STATE.ENDED);  // Still active with peer-2
  });

  test('group call ends when all participants leave', async () => {
    const call = createTestCall({ isGroupCall: true });
    await call.initiate(['peer-1']);

    const endSignal = VaniSignal.end({
      callId: call.id,
      fromPeer: 'peer-1',
      toPeer: 'local-peer',
    });
    await call.handleSignal(endSignal);

    expect(call.state).toBe(CALL_STATE.ENDED);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// VANI HUB TESTS
// ═══════════════════════════════════════════════════════════════════════════════

describe('VaniHub', () => {
  let hub;
  let signalsSent;
  
  beforeEach(() => {
    signalsSent = [];
    hub = new VaniHub({
      localPeerId: 'hub-peer',
      onSignal: (sig) => signalsSent.push(sig),
    });
  });

  afterEach(() => {
    hub.cleanup();
  });

  test('creates hub with local peer ID', () => {
    expect(hub.localPeerId).toBe('hub-peer');
    expect(hub.calls.size).toBe(0);
    expect(hub.activeCallId).toBe(null);
  });

  test('starts a call', async () => {
    const call = await hub.startCall({
      targetPeerIds: 'remote-peer',
      mediaType: [MEDIA_TYPE.AUDIO],
    });

    expect(hub.calls.size).toBe(1);
    expect(hub.activeCallId).toBe(call.id);
    expect(call.state).toBe(CALL_STATE.RINGING);
  });

  test('gets call by ID', async () => {
    const call = await hub.startCall({ targetPeerIds: 'peer' });
    
    expect(hub.getCall(call.id)).toBe(call);
    expect(hub.getCall('non-existent')).toBe(null);
  });

  test('gets active call', async () => {
    const call = await hub.startCall({ targetPeerIds: 'peer' });
    
    expect(hub.getActiveCall()).toBe(call);
  });

  test('handles incoming call offer', async () => {
    let incomingEvent = null;
    hub.on('incomingCall', (e) => { incomingEvent = e; });

    const offer = VaniSignal.offer({
      callId: 'incoming-call-123',
      fromPeer: 'caller',
      toPeer: 'hub-peer',
      mediaType: [MEDIA_TYPE.AUDIO],
    });

    await hub.handleSignal(offer);

    expect(incomingEvent).not.toBe(null);
    expect(incomingEvent.call.id).toBe('incoming-call-123');
    expect(hub.calls.has('incoming-call-123')).toBe(true);
  });

  test('accepts incoming call', async () => {
    const offer = VaniSignal.offer({
      callId: 'accept-call',
      fromPeer: 'caller',
      toPeer: 'hub-peer',
    });
    await hub.handleSignal(offer);

    const call = await hub.acceptCall('accept-call');

    expect(call.state).toBe(CALL_STATE.CONNECTING);
    expect(hub.activeCallId).toBe('accept-call');
  });

  test('rejects incoming call', async () => {
    const offer = VaniSignal.offer({
      callId: 'reject-call',
      fromPeer: 'caller',
      toPeer: 'hub-peer',
    });
    await hub.handleSignal(offer);

    hub.rejectCall('reject-call', CALL_END_REASON.BUSY);

    expect(hub.calls.has('reject-call')).toBe(false);
    
    const reject = signalsSent.find(s => s.type === VANI_CONFIG.messageTypes.CALL_REJECT);
    expect(reject).toBeDefined();
  });

  test('ends call', async () => {
    const call = await hub.startCall({ targetPeerIds: 'peer' });
    
    hub.endCall(call.id);

    expect(call.state).toBe(CALL_STATE.ENDED);
    
    const end = signalsSent.find(s => s.type === VANI_CONFIG.messageTypes.CALL_END);
    expect(end).toBeDefined();
  });

  test('removes call from map when ended', async () => {
    const call = await hub.startCall({ targetPeerIds: 'peer' });
    const callId = call.id;
    
    hub.endCall(callId);

    expect(hub.calls.has(callId)).toBe(false);
  });

  test('clears active call when ended', async () => {
    const call = await hub.startCall({ targetPeerIds: 'peer' });
    
    hub.endCall(call.id);

    expect(hub.activeCallId).toBe(null);
  });

  test('emits state change events', async () => {
    let stateEvent = null;
    hub.on('stateChange', (e) => { stateEvent = e; });

    await hub.startCall({ targetPeerIds: 'peer' });

    expect(stateEvent).not.toBe(null);
    expect(stateEvent.state).toBeDefined();
  });

  test('on/off event handlers', () => {
    const handler = vi.fn();
    
    hub.on('test', handler);
    hub._emit('test', { data: 1 });
    
    expect(handler).toHaveBeenCalledWith({ data: 1 });

    hub.off('test', handler);
    hub._emit('test', { data: 2 });
    
    expect(handler).toHaveBeenCalledTimes(1);
  });

  test('getStats returns hub info', async () => {
    await hub.startCall({ targetPeerIds: 'peer1' });
    
    const stats = hub.getStats();

    expect(stats.localPeerId).toBe('hub-peer');
    expect(stats.callCount).toBe(1);
    expect(stats.calls.length).toBe(1);
  });

  test('cleanup ends all calls', async () => {
    await hub.startCall({ targetPeerIds: 'peer1' });
    await hub.startCall({ targetPeerIds: 'peer2' });

    hub.cleanup();

    expect(hub.calls.size).toBe(0);
    expect(hub.activeCallId).toBe(null);
  });

  test('ends active call when accepting new one', async () => {
    // Start first call
    const call1 = await hub.startCall({ targetPeerIds: 'peer1' });
    
    // Receive incoming call
    const offer = VaniSignal.offer({
      callId: 'incoming',
      fromPeer: 'caller',
      toPeer: 'hub-peer',
    });
    await hub.handleSignal(offer);

    // Accept incoming - should end first call
    const call2 = await hub.acceptCall('incoming');

    expect(call1.state).toBe(CALL_STATE.ENDED);
    expect(hub.activeCallId).toBe('incoming');
  });

  test('routes signals to correct call', async () => {
    const call = await hub.startCall({ targetPeerIds: 'peer1' });
    
    // Send answer
    const answer = VaniSignal.answer({
      callId: call.id,
      fromPeer: 'peer1',
      toPeer: 'hub-peer',
    });
    await hub.handleSignal(answer);

    expect(call.state).toBe(CALL_STATE.CONNECTING);
  });

  test('ignores signals for unknown calls', async () => {
    const randomSignal = VaniSignal.iceCandidate({
      callId: 'unknown-call',
      fromPeer: 'someone',
      toPeer: 'hub-peer',
      candidate: 'test',
      sdpMid: '0',
      sdpMLineIndex: 0,
    });

    // Should not throw
    await hub.handleSignal(randomSignal);
    expect(hub.calls.size).toBe(0);
  });
});
