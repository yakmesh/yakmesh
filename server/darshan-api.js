/**
 * DARSHAN Content Streaming API
 * 
 * "Content stays on the altar. Pilgrims come to see."
 * 
 * Exposes the DARSHAN protocol as HTTP endpoints for:
 * - Content registration and listing
 * - Stream requests and chunk delivery
 * - View attestation and proof-of-viewing
 * - Bandwidth control and quality selection
 * 
 * DARSHAN is the streaming backbone for yakapp-studio content sharing.
 * Creators keep sovereignty — no copies leave unless explicitly permitted.
 * 
 * @module server/darshan-api
 * @license MIT
 * @copyright 2026 YAKMESH™ Contributors
 */

import { Router } from 'express';
import { createLogger } from '../utils/logger.js';

const log = createLogger('server:darshan');

/**
 * Create the DARSHAN API router.
 * 
 * @param {Object} params
 * @param {Object} params.darshanGateway - DarshanGateway instance (content host)
 * @param {Object} params.gossip - GossipProtocol instance
 * @param {Object} params.identity - NodeIdentity instance
 * @param {Function} params.writeLimiter - Express rate limiter for writes
 * @param {Function} params.requirePeerAuth - Peer auth middleware
 * @returns {Router} Express router mounted at /darshan
 */
export function createDarshanAPI({
  darshanGateway,
  gossip,
  identity,
  writeLimiter,
  requirePeerAuth,
}) {
  const router = Router();

  // ═══════════════════════════════════════════════════════════════════════════
  // STATUS
  // ═══════════════════════════════════════════════════════════════════════════

  router.get('/status', (req, res) => {
    res.json({
      darshan: 'operational',
      stats: darshanGateway.stats,
      contentCount: darshanGateway.contents.size,
      activeStreams: darshanGateway.streams.size,
    });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // CONTENT REGISTRY
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * GET /darshan/content — List available content (public metadata only)
   */
  router.get('/content', (req, res) => {
    const type = req.query.type || null;
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    
    let contents = [];
    for (const content of darshanGateway.contents.values()) {
      // Check exclusions
      if (darshanGateway.exclusions.has(content.contentId)) continue;
      
      if (type && content.contentType !== type) continue;
      
      contents.push(content.getPublicMetadata());
    }
    
    contents = contents.slice(0, limit);
    
    res.json({
      contents,
      total: contents.length,
      nodeId: identity.identity.nodeId,
    });
  });

  /**
   * GET /darshan/content/:contentId — Get content metadata
   */
  router.get('/content/:contentId', (req, res) => {
    const { contentId } = req.params;
    const content = darshanGateway.contents.get(contentId);
    
    if (!content || darshanGateway.exclusions.has(contentId)) {
      return res.status(404).json({ error: 'Content not found' });
    }

    res.json(content.getPublicMetadata());
  });

  /**
   * POST /darshan/content — Register content for sharing
   */
  router.post('/content', writeLimiter, requirePeerAuth, (req, res) => {
    const { path, name, description, contentType, mimeType, permissions, accessList } = req.body;
    
    if (!path) {
      return res.status(400).json({ error: 'path required' });
    }
    
    // Path traversal defense — reject .., absolute paths, and drive letters.
    // DARSHAN content paths must be relative within the host's content root.
    const normalizedPath = String(path).replace(/\\/g, '/');
    if (normalizedPath.includes('..') || normalizedPath.startsWith('/') || /^[a-zA-Z]:/.test(path)) {
      return res.status(400).json({ error: 'Invalid path: traversal or absolute paths not allowed' });
    }

    darshanGateway.registerContent({
      path,
      name,
      description,
      contentType,
      mimeType,
      permissions,
      accessList,
    }).then(result => {
      if (result.success !== false) {
        // Announce to mesh
        gossip.spreadRumor('darshan:content:available', {
          contentId: result.contentId || result.content?.contentId,
          hostNodeId: identity.identity.nodeId,
          metadata: result.content?.getPublicMetadata?.() || result,
        });
      }
      res.json(result);
    }).catch(error => {
      res.status(500).json({ error: error.message });
    });
  });

  /**
   * DELETE /darshan/content/:contentId — Unregister content
   */
  router.delete('/content/:contentId', writeLimiter, requirePeerAuth, (req, res) => {
    const { contentId } = req.params;
    
    const content = darshanGateway.contents.get(contentId);
    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }

    darshanGateway.contents.delete(contentId);
    if (content.path) {
      darshanGateway.contentByPath.delete(content.path);
    }

    // Announce removal to mesh
    gossip.spreadRumor('darshan:content:removed', {
      contentId,
      hostNodeId: identity.identity.nodeId,
    });

    res.json({ success: true });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // STREAMING
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * POST /darshan/stream — Request a stream
   */
  router.post('/stream', writeLimiter, requirePeerAuth, (req, res) => {
    const { contentId, quality, viewerNodeId } = req.body;
    
    if (!contentId) {
      return res.status(400).json({ error: 'contentId required' });
    }

    const content = darshanGateway.contents.get(contentId);
    if (!content || darshanGateway.exclusions.has(contentId)) {
      return res.status(404).json({ error: 'Content not found' });
    }

    // Check access if GUMBA-controlled
    if (content.accessList) {
      // Access verification would go through GUMBA — simplified for now
      const viewer = viewerNodeId || req.authenticatedPeer;
      if (!viewer) {
        return res.status(403).json({ error: 'GUMBA access proof required' });
      }
    }

    try {
      const stream = darshanGateway.createStream?.(contentId, {
        quality,
        viewerNodeId: viewerNodeId || req.authenticatedPeer || 'anonymous',
      });

      if (stream) {
        res.json({
          success: true,
          streamId: stream.streamId || stream.id,
          contentId,
          totalChunks: Math.ceil(content.size / content.chunkSize || 65536),
          chunkHashes: content.chunkHashes,
        });
      } else {
        // Fallback: return content info for direct streaming
        content.viewCount++;
        darshanGateway.stats.streamsCreated++;
        res.json({
          success: true,
          contentId,
          size: content.size,
          mimeType: content.mimeType,
          hash: content.hash,
        });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  /**
   * GET /darshan/stream/:streamId/chunk/:index — Get a chunk
   */
  router.get('/stream/:streamId/chunk/:index', (req, res) => {
    const { streamId, index } = req.params;
    const chunkIndex = parseInt(index);
    
    const stream = darshanGateway.streams.get(streamId);
    if (!stream) {
      return res.status(404).json({ error: 'Stream not found or expired' });
    }

    try {
      const chunk = stream.getChunk?.(chunkIndex);
      if (chunk) {
        res.set('Content-Type', 'application/octet-stream');
        res.set('X-Chunk-Index', chunkIndex.toString());
        res.set('X-Chunk-Hash', chunk.hash || '');
        res.send(chunk.data || chunk);
      } else {
        res.status(404).json({ error: 'Chunk not available' });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // VIEW ATTESTATION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * POST /darshan/attest — Submit a view attestation (proof of viewing)
   */
  router.post('/attest', requirePeerAuth, (req, res) => {
    const { contentId, viewerNodeId, streamId, duration, bytesConsumed } = req.body;
    
    if (!contentId || !viewerNodeId) {
      return res.status(400).json({ error: 'contentId and viewerNodeId required' });
    }

    try {
      const attestation = darshanGateway.createAttestation?.({
        contentId,
        viewerNodeId,
        streamId,
        duration,
        bytesConsumed,
      });

      if (attestation) {
        res.json({
          success: true,
          attestationId: attestation.attestationId || attestation.id,
        });
      } else {
        // Track basic stats even without full attestation module
        const content = darshanGateway.contents.get(contentId);
        if (content) {
          content.viewCount++;
          content.totalBytesServed += bytesConsumed || 0;
        }
        darshanGateway.stats.attestationsCreated++;
        res.json({ success: true, tracked: true });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  /**
   * GET /darshan/attestations/:contentId — Get view attestations for content
   */
  router.get('/attestations/:contentId', (req, res) => {
    const { contentId } = req.params;
    
    const attestations = [];
    for (const att of darshanGateway.attestations.values()) {
      if (att.contentId === contentId) {
        attestations.push(att.toJSON ? att.toJSON() : att);
      }
    }

    res.json({ attestations, total: attestations.length });
  });

  log.info('✓ DARSHAN API initialized (content streaming + attestation)');

  return router;
}

/**
 * Wire DARSHAN gossip handlers into the mesh rumor stream.
 */
export function wireDarshanGossip(mesh, darshanGateway) {
  mesh.on('rumor', (topic, data, origin) => {
    // Content availability announcements from other nodes
    if (topic === 'darshan:content:available') {
      darshanGateway.emit?.('remote:content:available', data);
    }

    // Content removal announcements
    if (topic === 'darshan:content:removed') {
      darshanGateway.emit?.('remote:content:removed', data);
    }
  });

  log.info('✓ DARSHAN gossip handlers wired into mesh');
}
