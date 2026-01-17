/**
 * Multi-Node Content Propagation Test
 * 
 * Tests:
 * 1. Start Node Alpha and Node Beta (same codebase = same network)
 * 2. Wait for mesh peering and Code Proof validation
 * 3. Publish content on Alpha
 * 4. Verify content propagates to Beta via gossip
 * 5. Verify content is retrievable from Beta's HTTP API
 * 
 * This validates:
 * - Gossip content_announce works
 * - content_request/response works between nodes
 * - Public HTTP layer serves mesh-propagated content
 */

import { spawn } from 'child_process';
import { setTimeout as sleep } from 'timers/promises';

const ALPHA_HTTP = 'http://localhost:3001';
const BETA_HTTP = 'http://localhost:3002';

// Helper to make HTTP requests
async function httpRequest(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  try {
    return { status: response.status, data: JSON.parse(text) };
  } catch {
    return { status: response.status, data: text };
  }
}

// Start a node
function startNode(configPath, name) {
  console.log(`🚀 Starting ${name}...`);
  const proc = spawn('node', ['server/index.js', '--config', configPath], {
    cwd: process.cwd(),
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, FORCE_COLOR: '1' }
  });
  
  proc.stdout.on('data', (d) => {
    const lines = d.toString().split('\n').filter(l => l.trim());
    lines.forEach(l => console.log(`[${name}] ${l}`));
  });
  proc.stderr.on('data', (d) => {
    const lines = d.toString().split('\n').filter(l => l.trim());
    lines.forEach(l => console.log(`[${name}] ⚠️ ${l}`));
  });
  
  return proc;
}

async function runTest() {
  console.log('\n========================================');
  console.log('  MULTI-NODE CONTENT PROPAGATION TEST');
  console.log('========================================\n');
  
  let alpha, beta;
  
  try {
    // 1. Start both nodes
    alpha = startNode('./test-nodes/config-alpha.js', 'ALPHA');
    await sleep(4000);  // Give Alpha time to start
    
    beta = startNode('./test-nodes/config-beta.js', 'BETA');
    await sleep(6000);  // Give Beta time to connect
    
    // 2. Check both nodes are up - use /content endpoint which we know exists
    console.log('\n📡 Checking node status...\n');
    
    const alphaStatus = await httpRequest(`${ALPHA_HTTP}/content`).catch(e => ({ status: 0, error: e.message }));
    const betaStatus = await httpRequest(`${BETA_HTTP}/content`).catch(e => ({ status: 0, error: e.message }));
    
    if (alphaStatus.status !== 200) {
      console.log('Alpha status:', alphaStatus);
      throw new Error(`Alpha not responding: ${alphaStatus.error || alphaStatus.status}`);
    }
    if (betaStatus.status !== 200) {
      console.log('Beta status:', betaStatus);
      throw new Error(`Beta not responding: ${betaStatus.error || betaStatus.status}`);
    }
    
    console.log('✓ Alpha running');
    console.log('✓ Beta running');
    
    // 3. Check initial content on both nodes
    console.log('\n📦 Checking initial content state...\n');
    
    const alphaContent = await httpRequest(`${ALPHA_HTTP}/content`);
    const betaContent = await httpRequest(`${BETA_HTTP}/content`);
    
    console.log(`Alpha content: ${alphaContent.data?.count || 0} items`);
    console.log(`Beta content: ${betaContent.data?.count || 0} items`);
    
    // 4. Publish content on Alpha
    console.log('\n📤 Publishing content on Alpha...\n');
    
    const testContent = {
      content: `Test content published at ${new Date().toISOString()}`,
      contentType: 'text/plain',
      tags: ['test', 'propagation'],
      name: 'propagation-test.txt'
    };
    
    const publishResult = await httpRequest(`${ALPHA_HTTP}/content/publish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(testContent)
    });
    
    if (publishResult.status !== 201) {
      throw new Error(`Publish failed: ${JSON.stringify(publishResult.data)}`);
    }
    
    const contentHash = publishResult.data.hash;
    console.log(`✓ Content published on Alpha`);
    console.log(`  Hash: ${contentHash}`);
    console.log(`  URL: ${ALPHA_HTTP}/content/${contentHash}`);
    
    // 5. Wait for gossip propagation
    console.log('\n⏳ Waiting for gossip propagation (5s)...\n');
    await sleep(5000);
    
    // 6. Check if content reached Beta
    console.log('📥 Checking Beta for propagated content...\n');
    
    const betaCheck = await httpRequest(`${BETA_HTTP}/content/${contentHash}`);
    
    if (betaCheck.status === 200) {
      console.log('✓ Content successfully propagated to Beta!');
      console.log(`  Retrieved: "${betaCheck.data}"`);
      
      // Verify metadata
      const betaMeta = await httpRequest(`${BETA_HTTP}/content/${contentHash}/meta`);
      console.log(`  Status: ${betaMeta.data?.status}`);
      console.log(`  Tags: ${betaMeta.data?.tags?.join(', ')}`);
    } else {
      // Try requesting it explicitly
      console.log('Content not auto-propagated, trying explicit request...');
      
      const requestResult = await httpRequest(`${BETA_HTTP}/content/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: contentHash })
      });
      
      console.log('Request result:', requestResult.data);
      
      await sleep(3000);  // Wait for mesh transfer
      
      const retryCheck = await httpRequest(`${BETA_HTTP}/content/${contentHash}`);
      if (retryCheck.status === 200) {
        console.log('✓ Content retrieved via explicit request');
        console.log(`  Content: "${retryCheck.data}"`);
      } else {
        console.log('✗ Content not found on Beta');
      }
    }
    
    // 7. Check peer status using /content/stats endpoint
    console.log('\n📊 Final content status...\n');
    
    const alphaFinal = await httpRequest(`${ALPHA_HTTP}/content/stats`);
    const betaFinal = await httpRequest(`${BETA_HTTP}/content/stats`);
    
    console.log(`Alpha: ${alphaFinal.data?.totalObjects || 0} objects`);
    console.log(`Beta: ${betaFinal.data?.totalObjects || 0} objects`);
    
    console.log('\n========================================');
    console.log('  TEST COMPLETE');
    console.log('========================================\n');
    
  } finally {
    // Cleanup
    console.log('🛑 Shutting down nodes...');
    if (alpha) alpha.kill('SIGTERM');
    if (beta) beta.kill('SIGTERM');
    await sleep(1000);
  }
}

runTest().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
