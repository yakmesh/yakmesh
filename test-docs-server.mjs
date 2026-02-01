#!/usr/bin/env node
/**
 * Test Documentation Server
 * Run: node test-docs-server.mjs
 */

import express from 'express';
import { serveDocsFile, getBundleInfo, BUNDLE_HASH } from './embedded-docs/index.js';
import { deriveNetworkName } from './oracle/network-identity.js';

const app = express();
const port = 9999;

// Order matters! Specific routes first
app.get('/docs/_bundle', (req, res) => res.json(getBundleInfo()));
app.get('/docs/index.html', (req, res) => {
  console.log('[' + new Date().toISOString() + '] Serving index.html');
  serveDocsFile('index.html', res);
});
app.get('/docs/', (req, res) => {
  console.log('[' + new Date().toISOString() + '] Serving / -> index.html');
  serveDocsFile('index.html', res);
});
app.get('/docs', (req, res) => res.redirect('/docs/'));
app.get('/docs/:file', (req, res) => {
  const file = req.params.file;
  console.log('[' + new Date().toISOString() + '] Serving:', file);
  if (!file || file === '') {
    serveDocsFile('index.html', res);
  } else {
    serveDocsFile(file, res);
  }
});

// Serve assets (silhouettes, etc.) - CSS references ../assets/ from /docs/
app.get('/assets/*', (req, res) => {
  const assetPath = req.path.substring(1); // Remove leading /
  console.log('[' + new Date().toISOString() + '] Asset:', assetPath);
  serveDocsFile(assetPath, res);
});

app.get('/', (req, res) => res.redirect('/docs/'));

const server = app.listen(port, '0.0.0.0', () => {
  const ioName = deriveNetworkName(BUNDLE_HASH, 3);
  console.log('');
  console.log('📦 YAKMESH Test Documentation Server');
  console.log('=====================================');
  console.log('');
  console.log('  URL:     http://localhost:' + port + '/docs/');
  console.log('  Bundle:  ' + ioName + ' (' + BUNDLE_HASH.substring(0, 8) + '...)');
  console.log('  Files:   ' + getBundleInfo().fileCount);
  console.log('');
  console.log('  Press Ctrl+C to stop.');
  console.log('');
});

// Keep alive
process.on('SIGINT', () => {
  console.log('\nShutting down...');
  server.close(() => process.exit(0));
});
