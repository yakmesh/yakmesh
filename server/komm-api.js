/**
 * KOMM Stack API — KATHA + VANI + YURT + GUMBA
 * 
 * Exposes the Himalayan chat/voice/room/access protocols as HTTP + WS endpoints.
 * This is the backend that yakapp's MeshBridge and terminal clients consume.
 * 
 * Architecture:
 *   yakapp (GUI)     ─── HTTP/WS ───┐
 *   terminal (CLI)   ─── HTTP/WS ───┤── KOMM API ── yakmesh-node protocols
 *   external clients ─── HTTP/WS ───┘
 * 
 * @module server/komm-api
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { Router } from 'express';
import { createLogger } from '../utils/logger.js';

const log = createLogger('server:komm');

/**
 * Create the KOMM stack API router.
 * 
 * @param {Object} params
 * @param {Object} params.kathaHub - KathaHub instance (chat messaging)
 * @param {Object} params.vaniHub - VaniHub instance (voice/video)
 * @param {Object} params.yurtHub - YurtHub instance (room directory)
 * @param {Object} params.gumbaHub - GumbaHub instance (access control)
 * @param {Object} params.gossip - GossipProtocol instance (for broadcasting)
 * @param {Object} params.identity - NodeIdentity instance
 * @param {Function} params.writeLimiter - Express rate limiter for writes
 * @param {Function} params.requirePeerAuth - Peer auth middleware
 * @returns {Router} Express router mounted at /komm
 */
export function createKommAPI({
  kathaHub,
  vaniHub,
  yurtHub,
  gumbaHub,
  gossip,
  identity,
  writeLimiter,
  requirePeerAuth,
}) {
  const router = Router();

  // ═══════════════════════════════════════════════════════════════════════════
  // KOMM STATUS
  // ═══════════════════════════════════════════════════════════════════════════

  router.get('/status', (req, res) => {
    res.json({
      komm: 'operational',
      katha: {
        channels: kathaHub.channels.size,
      },
      vani: {
        activeCalls: vaniHub.calls.size,
        activeCallId: vaniHub.activeCallId,
      },
      yurt: {
        rooms: yurtHub.directory.entries.size,
        ownRooms: yurtHub.directory.ownEntries?.size || 0,
      },
      gumba: {
        bundles: gumbaHub.bundles.size,
        sessions: gumbaHub.sessions.size,
        stats: gumbaHub.stats,
      },
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // KATHA — Chat Messaging
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * GET /komm/katha/channels — List active channels
   */
  router.get('/katha/channels', (req, res) => {
    const channels = [];
    for (const [id, channel] of kathaHub.channels) {
      channels.push({
        channelId: id,
        messageCount: channel.messages?.length || 0,
        typingUsers: channel.getTypingUsers?.() || [],
      });
    }
    res.json({ channels });
  });

  /**
   * GET /komm/katha/channel/:channelId — Get channel messages
   */
  router.get('/katha/channel/:channelId', (req, res) => {
    const { channelId } = req.params;
    const since = parseInt(req.query.since) || 0;
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    
    const channel = kathaHub.channels.get(channelId);
    if (!channel) {
      return res.json({ messages: [], exists: false });
    }

    let messages = channel.messages || [];
    if (since > 0) {
      messages = messages.filter(m => m.timestamp > since);
    }
    messages = messages.slice(-limit);

    res.json({
      channelId,
      messages: messages.map(m => m.toJSON ? m.toJSON() : m),
      typingUsers: channel.getTypingUsers?.() || [],
      exists: true,
    });
  });

  /**
   * POST /komm/katha/send — Send a message (broadcast via gossip)
   */
  router.post('/katha/send', writeLimiter, requirePeerAuth, (req, res) => {
    const { channelId, type, ...eventData } = req.body;
    
    if (!channelId) {
      return res.status(400).json({ error: 'channelId required' });
    }

    const event = { channelId, type: type || 'katha:text', ...eventData };
    
    // Process locally
    const result = kathaHub.handleEvent(event);
    
    // Broadcast to mesh
    gossip.spreadRumor('katha:event', {
      ...event,
      origin: identity.identity.nodeId,
      timestamp: Date.now(),
    });

    res.json({ success: true, result });
  });

  /**
   * POST /komm/katha/typing — Typing indicator
   */
  router.post('/katha/typing', requirePeerAuth, (req, res) => {
    const { channelId, userId: bodyUserId, typing } = req.body;
    // Use authenticated peer identity when available; fall back to body for localhost
    const userId = req.authenticatedPeer || bodyUserId;
    
    if (!channelId || !userId) {
      return res.status(400).json({ error: 'channelId and userId required' });
    }

    const channel = kathaHub.getChannel(channelId);
    channel.setTyping(userId, typing !== false);

    // Ephemeral — broadcast but don't persist
    gossip.spreadRumor('katha:typing', {
      channelId,
      userId,
      typing: typing !== false,
      origin: identity.identity.nodeId,
    });

    res.json({ success: true });
  });

  /**
   * POST /komm/katha/reaction — Add/remove reaction
   */
  router.post('/katha/reaction', writeLimiter, requirePeerAuth, (req, res) => {
    const { channelId, messageId, userId: bodyUserId, emoji, remove } = req.body;
    // Use authenticated peer identity when available; fall back to body for localhost
    const userId = req.authenticatedPeer || bodyUserId;
    
    if (!channelId || !messageId || !userId || !emoji) {
      return res.status(400).json({ error: 'channelId, messageId, userId, and emoji required' });
    }

    const event = {
      channelId,
      messageId,
      userId,
      emoji,
      type: remove ? 'katha:reaction:remove' : 'katha:reaction:add',
    };

    const result = kathaHub.handleEvent(event);
    gossip.spreadRumor('katha:event', { ...event, origin: identity.identity.nodeId });

    res.json({ success: true, result });
  });

  /**
   * POST /komm/katha/read — Mark messages as read
   */
  router.post('/katha/read', requirePeerAuth, (req, res) => {
    const { channelId, userId: bodyUserId, lastReadMessageId, lastReadTimestamp } = req.body;
    // Use authenticated peer identity when available; fall back to body for localhost
    const userId = req.authenticatedPeer || bodyUserId;
    
    if (!channelId || !userId) {
      return res.status(400).json({ error: 'channelId and userId required' });
    }

    const event = {
      channelId,
      userId,
      lastReadMessageId,
      lastReadTimestamp: lastReadTimestamp || Date.now(),
      type: 'katha:read',
    };

    kathaHub.handleEvent(event);
    gossip.spreadRumor('katha:event', { ...event, origin: identity.identity.nodeId });

    res.json({ success: true });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // VANI — Voice/Video Calling
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * GET /komm/vani/calls — List active calls
   */
  router.get('/vani/calls', (req, res) => {
    const calls = [];
    for (const [id, call] of vaniHub.calls) {
      calls.push({
        callId: id,
        state: call.state,
        mediaType: call.mediaType,
        participants: call.participants?.size || 0,
        startedAt: call.startedAt,
      });
    }
    res.json({ calls, activeCallId: vaniHub.activeCallId });
  });

  /**
   * POST /komm/vani/call — Start a new call
   */
  router.post('/vani/call', writeLimiter, requirePeerAuth, (req, res) => {
    const { targetPeerIds, mediaType, bundleId, isGroupCall } = req.body;
    
    if (!targetPeerIds || !Array.isArray(targetPeerIds)) {
      return res.status(400).json({ error: 'targetPeerIds array required' });
    }

    try {
      const call = vaniHub.startCall({
        targetPeerIds,
        mediaType,
        bundleId,
        isGroupCall,
      });

      res.json({ success: true, callId: call.id });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  /**
   * POST /komm/vani/signal — Forward WebRTC signal
   */
  router.post('/vani/signal', requirePeerAuth, (req, res) => {
    const { signal } = req.body;
    
    if (!signal) {
      return res.status(400).json({ error: 'signal object required' });
    }

    try {
      vaniHub.handleSignal(signal);
      
      // Forward signal through mesh gossip
      gossip.spreadRumor('vani:signal', {
        signal,
        origin: identity.identity.nodeId,
      });

      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  /**
   * POST /komm/vani/call/:callId/end — End a call
   */
  router.post('/vani/call/:callId/end', requirePeerAuth, (req, res) => {
    const { callId } = req.params;
    const { reason } = req.body;
    
    const call = vaniHub.calls.get(callId);
    if (!call) {
      return res.status(404).json({ error: 'Call not found' });
    }

    call.end(reason || 'USER_HANGUP');
    res.json({ success: true });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // YURT — Room Directory & Discovery  
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * GET /komm/yurt/rooms — List discovered rooms
   */
  router.get('/yurt/rooms', (req, res) => {
    const tag = req.query.tag || null;
    const includeExpired = req.query.includeExpired === 'true';
    
    let entries = yurtHub.directory.list();
    
    if (tag) {
      entries = entries.filter(e => e.tags?.includes(tag));
    }
    if (!includeExpired) {
      entries = entries.filter(e => !e.isExpired?.());
    }

    res.json({
      rooms: entries.map(e => e.toJSON ? e.toJSON() : e),
      total: entries.length,
    });
  });

  /**
   * GET /komm/yurt/room/:bundleId — Get room details
   */
  router.get('/yurt/room/:bundleId', (req, res) => {
    const { bundleId } = req.params;
    const entry = yurtHub.directory.get(bundleId);
    
    if (!entry) {
      return res.status(404).json({ error: 'Room not found' });
    }

    res.json(entry.toJSON ? entry.toJSON() : entry);
  });

  /**
   * POST /komm/yurt/publish — Publish a room to the directory
   */
  router.post('/yurt/publish', writeLimiter, requirePeerAuth, (req, res) => {
    const { bundleId, name, description, tags, visibility } = req.body;
    
    if (!bundleId) {
      return res.status(400).json({ error: 'bundleId required' });
    }

    try {
      const result = yurtHub.publishRoom(bundleId, {
        name,
        description,
        tags,
        visibility,
      });

      res.json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  /**
   * POST /komm/yurt/search — Search for rooms via gossip
   */
  router.post('/yurt/search', requirePeerAuth, (req, res) => {
    const { query, tags, limit } = req.body;
    
    try {
      const results = yurtHub.search?.({ query, tags, limit }) ||
                      yurtHub.gossip.query?.({ query, tags }) ||
                      { results: [] };
      res.json(results);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  /**
   * DELETE /komm/yurt/room/:bundleId — Unpublish a room
   */
  router.delete('/yurt/room/:bundleId', writeLimiter, requirePeerAuth, (req, res) => {
    const { bundleId } = req.params;
    
    try {
      yurtHub.unpublishRoom?.(bundleId);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // GUMBA — Access Control (Bundles, Proofs, Membership)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * GET /komm/gumba/bundles — List all bundles
   */
  router.get('/gumba/bundles', (req, res) => {
    res.json({ bundles: gumbaHub.listBundles() });
  });

  /**
   * GET /komm/gumba/bundle/:bundleId — Get bundle info
   */
  router.get('/gumba/bundle/:bundleId', (req, res) => {
    const { bundleId } = req.params;
    const bundle = gumbaHub.getBundle(bundleId);
    
    if (!bundle) {
      return res.status(404).json({ error: 'Bundle not found' });
    }

    res.json(bundle.getInfo());
  });

  /**
   * POST /komm/gumba/bundle — Create a new bundle (room)
   */
  router.post('/gumba/bundle', writeLimiter, requirePeerAuth, (req, res) => {
    const { bundleId, name, description, maxMembers } = req.body;
    
    if (!bundleId) {
      return res.status(400).json({ error: 'bundleId required' });
    }

    try {
      const info = gumbaHub.createBundle(bundleId, { name, description, maxMembers });
      res.json({ success: true, bundle: info });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

  /**
   * POST /komm/gumba/bundle/:bundleId/access — Request access to a bundle
   */
  router.post('/gumba/bundle/:bundleId/access', writeLimiter, requirePeerAuth, (req, res) => {
    const { bundleId } = req.params;
    const { proof, visitorNodeId } = req.body;
    
    if (!proof) {
      return res.status(400).json({ error: 'proof object required' });
    }

    gumbaHub.handleAccessRequest(
      bundleId,
      proof,
      visitorNodeId || req.authenticatedPeer || 'unknown'
    ).then(result => {
      res.json(result);
    }).catch(error => {
      res.status(500).json({ error: error.message });
    });
  });

  /**
   * POST /komm/gumba/bundle/:bundleId/member — Add a member
   */
  router.post('/gumba/bundle/:bundleId/member', writeLimiter, requirePeerAuth, (req, res) => {
    const { bundleId } = req.params;
    const { dokoId, role } = req.body;
    
    if (!dokoId) {
      return res.status(400).json({ error: 'dokoId required' });
    }

    const bundle = gumbaHub.getBundle(bundleId);
    if (!bundle) {
      return res.status(404).json({ error: 'Bundle not found' });
    }

    try {
      const result = bundle.addMember(dokoId, role);
      
      gossip.spreadRumor('gumba:member:added', {
        bundleId,
        dokoId,
        role,
        origin: identity.identity.nodeId,
      });

      res.json({ success: true, result });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

  /**
   * DELETE /komm/gumba/bundle/:bundleId/member/:dokoId — Remove a member
   */
  router.delete('/gumba/bundle/:bundleId/member/:dokoId', writeLimiter, requirePeerAuth, (req, res) => {
    const { bundleId, dokoId } = req.params;
    
    const bundle = gumbaHub.getBundle(bundleId);
    if (!bundle) {
      return res.status(404).json({ error: 'Bundle not found' });
    }

    try {
      bundle.removeMember(dokoId);
      
      gossip.spreadRumor('gumba:member:removed', {
        bundleId,
        dokoId,
        origin: identity.identity.nodeId,
      });

      res.json({ success: true });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

  /**
   * POST /komm/gumba/bundle/:bundleId/message — Send message to bundle (ANNEX-encrypted)
   */
  router.post('/gumba/bundle/:bundleId/message', writeLimiter, requirePeerAuth, (req, res) => {
    const { bundleId } = req.params;
    const { sessionId, content, contentType } = req.body;
    
    const bundle = gumbaHub.getBundle(bundleId);
    if (!bundle) {
      return res.status(404).json({ error: 'Bundle not found' });
    }

    // Verify session
    const session = gumbaHub.sessions.get(sessionId);
    if (!session || session.bundleId !== bundleId) {
      return res.status(403).json({ error: 'Invalid or expired session' });
    }
    if (session.expiresAt < Date.now()) {
      gumbaHub.sessions.delete(sessionId);
      return res.status(403).json({ error: 'Session expired' });
    }

    try {
      const result = bundle.addMessage({
        content,
        contentType,
        senderDokoId: session.dokoId,
        role: session.role,
      });
      
      // Broadcast encrypted via gossip (GUMBA handles encryption)
      gossip.spreadRumor('gumba:message', {
        bundleId,
        origin: identity.identity.nodeId,
        encrypted: true,
        timestamp: Date.now(),
      });

      res.json({ success: true, messageId: result?.messageId });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  log.info('✓ KOMM API initialized (KATHA + VANI + YURT + GUMBA)');

  return router;
}

/**
 * Wire KOMM gossip handlers into the mesh rumor stream.
 * Called once during server initialization.
 * 
 * @param {Object} mesh - MeshNetwork instance
 * @param {Object} kathaHub - KathaHub instance
 * @param {Object} vaniHub - VaniHub instance
 * @param {Object} yurtHub - YurtHub instance
 * @param {Object} gumbaHub - GumbaHub instance
 */
export function wireKommGossip(mesh, kathaHub, vaniHub, yurtHub, gumbaHub) {
  mesh.on('rumor', (topic, data, origin) => {
    // KATHA events (chat messages, reactions, edits, deletes)
    if (topic === 'katha:event') {
      kathaHub.handleEvent(data);
    }

    // KATHA typing indicators (ephemeral)
    if (topic === 'katha:typing') {
      const channel = kathaHub.getChannel(data.channelId);
      if (channel) {
        channel.setTyping(data.userId, data.typing);
      }
    }

    // VANI signals (WebRTC signaling for calls)
    if (topic === 'vani:signal') {
      vaniHub.handleSignal(data.signal);
    }

    // YURT room announcements
    if (topic === 'yurt:register' || topic === 'yurt:announce') {
      yurtHub.gossip?.handleRemoteAnnounce?.(data) ||
        yurtHub.directory.add?.(data);
    }

    // YURT room removals
    if (topic === 'yurt:unregister') {
      yurtHub.directory.remove?.(data.entryId || data.bundleId);
    }

    // YURT relay (message forwarding between rooms on different nodes)
    if (topic === 'yurt:relay') {
      // Deliver to local KATHA channel if we host this bundle
      if (gumbaHub.getBundle(data.bundleId)) {
        kathaHub.handleEvent({
          channelId: data.bundleId,
          ...data.event,
        });
      }
    }

    // GUMBA member changes
    if (topic === 'gumba:member:added') {
      const bundle = gumbaHub.getBundle(data.bundleId);
      if (bundle) {
        try { bundle.addMember(data.dokoId, data.role); } catch { /* already member */ }
      }
    }
    if (topic === 'gumba:member:removed') {
      const bundle = gumbaHub.getBundle(data.bundleId);
      if (bundle) {
        try { bundle.removeMember(data.dokoId); } catch { /* not member */ }
      }
    }
  });

  log.info('✓ KOMM gossip handlers wired into mesh');
}
