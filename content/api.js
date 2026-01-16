/**
 * YAKMESH™ Public Content API
 * HTTP endpoints for public content delivery
 * 
 * Public (no auth required):
 * - GET /content/:hash - Fetch content by hash
 * - GET /content/:hash/meta - Fetch metadata only
 * - GET /content/:hash/proof - Fetch consensus proof
 * - GET /content/list - List available content
 * 
 * Authenticated (rate limited):
 * - POST /content/publish - Publish new content
 * - DELETE /content/:hash - Remove content (owner only)
 * 
 * @module content/api
 * @license MIT
 * @copyright 2026 YAKMESH Contributors
 */

import { Router } from 'express';
import { ContentStore, ContentType, ContentStatus, computeContentHash } from './store.js';

/**
 * Create content API router
 */
export function createContentAPI(contentStore, options = {}) {
  const router = Router();
  
  const {
    writeLimiter,
    readLimiter,
    validateString,
  } = options;

  // =========================================
  // PUBLIC READ ENDPOINTS (No Auth)
  // =========================================

  /**
   * GET /content/:hash
   * Fetch content by hash with optional proof
   * 
   * Query params:
   * - proof=1 : Include consensus proof in response headers
   * - download=1 : Force download (Content-Disposition)
   */
  router.get('/:hash', readLimiter, (req, res) => {
    const { hash } = req.params;
    const includeProof = req.query.proof === '1';
    const download = req.query.download === '1';

    // Get content with metadata
    const result = contentStore.getWithProof(hash);
    
    if (!result) {
      return res.status(404).json({ 
        error: 'Content not found',
        hash,
        hint: 'Content may not have synced yet. Try again later.',
      });
    }

    // Set content type
    res.setHeader('Content-Type', result.meta?.contentType || 'application/octet-stream');
    res.setHeader('Content-Length', result.meta?.size || result.content.length);
    res.setHeader('X-Content-Hash', result.hash);
    res.setHeader('X-Content-Status', result.meta?.status || 'unknown');
    
    // Cache headers (immutable content = cache forever)
    if (result.verified) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=60');
    }

    // Include proof in headers if requested
    if (includeProof && result.proof) {
      res.setHeader('X-Consensus-Proof', JSON.stringify(result.proof));
      res.setHeader('X-Verified', result.verified ? 'true' : 'false');
    }

    // Download disposition
    if (download && result.meta?.name) {
      res.setHeader('Content-Disposition', `attachment; filename="${result.meta.name}"`);
    }

    // Send content
    res.send(result.content);
  });

  /**
   * GET /content/:hash/meta
   * Fetch metadata only (no content body)
   */
  router.get('/:hash/meta', readLimiter, (req, res) => {
    const { hash } = req.params;
    const meta = contentStore.getMeta(hash);
    
    if (!meta) {
      return res.status(404).json({ error: 'Content not found', hash });
    }

    res.json(meta.toJSON ? meta.toJSON() : meta);
  });

  /**
   * GET /content/:hash/proof
   * Fetch consensus proof for light client verification
   */
  router.get('/:hash/proof', readLimiter, (req, res) => {
    const { hash } = req.params;
    const meta = contentStore.getMeta(hash);
    
    if (!meta) {
      return res.status(404).json({ error: 'Content not found', hash });
    }

    if (!meta.consensusProof) {
      return res.status(404).json({ 
        error: 'No consensus proof yet',
        hash,
        status: meta.status,
        hint: 'Content may still be pending consensus.',
      });
    }

    res.json({
      hash,
      verified: meta.status === ContentStatus.VERIFIED,
      proof: meta.consensusProof.toJSON ? meta.consensusProof.toJSON() : meta.consensusProof,
    });
  });

  /**
   * GET /content/list
   * List available content
   * 
   * Query params:
   * - tag=<tag> : Filter by tag
   * - status=<status> : Filter by status (local, pending, verified)
   * - limit=<n> : Max results (default 100)
   * - offset=<n> : Pagination offset
   */
  router.get('/', readLimiter, (req, res) => {
    const { tag, status, limit = 100, offset = 0 } = req.query;
    
    const items = contentStore.list({
      tag,
      status,
      limit: Math.min(parseInt(limit) || 100, 1000),
      offset: parseInt(offset) || 0,
    });

    res.json({
      items,
      count: items.length,
      stats: contentStore.getStats(),
    });
  });

  /**
   * HEAD /content/:hash
   * Check if content exists (useful for CDN/cache validation)
   */
  router.head('/:hash', readLimiter, (req, res) => {
    const { hash } = req.params;
    
    if (contentStore.has(hash)) {
      const meta = contentStore.getMeta(hash);
      res.setHeader('Content-Type', meta?.contentType || 'application/octet-stream');
      res.setHeader('Content-Length', meta?.size || 0);
      res.setHeader('X-Content-Hash', hash);
      res.setHeader('X-Content-Status', meta?.status || 'unknown');
      res.status(200).end();
    } else {
      res.status(404).end();
    }
  });

  // =========================================
  // AUTHENTICATED WRITE ENDPOINTS
  // =========================================

  /**
   * POST /content/publish
   * Publish new content to the mesh
   * 
   * Body (JSON):
   * {
   *   content: <string|object>,
   *   contentType?: <mime-type>,
   *   name?: <human-readable-name>,
   *   tags?: [<tag>, ...],
   *   ttl?: <seconds>
   * }
   * 
   * Body (multipart/form-data):
   * - file: uploaded file
   * - name: optional name
   * - tags: comma-separated tags
   */
  router.post('/publish', writeLimiter, async (req, res) => {
    try {
      let content;
      let options = {};

      // Handle JSON body
      if (req.is('application/json')) {
        if (!req.body.content) {
          return res.status(400).json({ error: 'Content required' });
        }
        content = req.body.content;
        options = {
          contentType: req.body.contentType,
          name: req.body.name,
          tags: req.body.tags || [],
          ttl: req.body.ttl || 0,
        };
      } 
      // Handle raw body
      else if (req.body && Buffer.isBuffer(req.body)) {
        content = req.body;
        options = {
          contentType: req.headers['content-type'] || 'application/octet-stream',
          name: req.headers['x-content-name'],
          tags: req.headers['x-content-tags']?.split(',') || [],
        };
      }
      // Handle form data (basic - for full multipart use multer)
      else if (req.body?.content) {
        content = req.body.content;
        options = {
          contentType: req.body.contentType,
          name: req.body.name,
          tags: typeof req.body.tags === 'string' ? req.body.tags.split(',') : req.body.tags,
        };
      }
      else {
        return res.status(400).json({ error: 'Content required in body' });
      }

      // Store and publish
      const result = await contentStore.store(content, options);

      res.status(201).json({
        success: true,
        hash: result.hash,
        status: result.status,
        meta: result.meta?.toJSON ? result.meta.toJSON() : result.meta,
        url: `/content/${result.hash}`,
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  /**
   * POST /content/request
   * Request content from mesh (if not locally available)
   */
  router.post('/request', writeLimiter, async (req, res) => {
    const { hash } = req.body;
    
    if (!hash) {
      return res.status(400).json({ error: 'Hash required' });
    }

    try {
      // Check local first
      if (contentStore.has(hash)) {
        return res.json({
          found: true,
          local: true,
          hash,
        });
      }

      // Request from mesh
      const result = await contentStore.request(hash);
      
      res.json({
        found: true,
        local: false,
        hash: result.hash,
        meta: result.meta,
      });
    } catch (error) {
      res.status(404).json({
        found: false,
        hash,
        error: error.message,
      });
    }
  });

  /**
   * DELETE /content/:hash
   * Remove content (local only - cannot remove from mesh)
   */
  router.delete('/:hash', writeLimiter, (req, res) => {
    const { hash } = req.params;
    
    if (!contentStore.has(hash)) {
      return res.status(404).json({ error: 'Content not found', hash });
    }

    // Note: This only removes locally - content may still exist on other nodes
    contentStore.delete(hash);

    res.json({
      deleted: true,
      hash,
      note: 'Content removed locally. Other mesh nodes may still have copies.',
    });
  });

  /**
   * GET /content/stats
   * Get content store statistics
   */
  router.get('/stats', readLimiter, (req, res) => {
    res.json(contentStore.getStats());
  });

  /**
   * POST /content/verify
   * Compute hash for content without storing
   * Useful for clients to verify content integrity
   */
  router.post('/verify', readLimiter, (req, res) => {
    const content = req.body.content || req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'Content required' });
    }

    const hash = computeContentHash(content);
    
    res.json({
      hash,
      exists: contentStore.has(hash),
    });
  });

  return router;
}

export default createContentAPI;
