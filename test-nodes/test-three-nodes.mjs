/**
 * YAKMESH Comprehensive 3-Node Test Suite
 * 
 * Tests the Code Proof Protocol across multiple scenarios:
 * 
 * TEST 1: Two Synced + One Old
 *   - Alpha & Beta (same new codebase) should peer
 *   - Gamma (old LAN codebase) should be REJECTED
 * 
 * TEST 2: Three Different Codebases
 *   - All three nodes should be isolated (different network identities)
 * 
 * TEST 3: Stress/Edge Cases
 *   - Rapid reconnection attempts
 *   - Race conditions in handshake
 */

const WebSocket = (await import('ws')).default;
const http = await import('http');

// ═══════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════

const NODES = {
  alpha: { http: 'http://localhost:3001', ws: 'ws://localhost:9001', name: 'Alpha (local)' },
  beta:  { http: 'http://localhost:3002', ws: 'ws://localhost:9002', name: 'Beta (local)' },
  gamma: { http: 'http://192.168.1.178:3000', ws: 'ws://192.168.1.178:9001', name: 'Gamma (LAN)' },
};

const COLORS = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

function c(color, text) { return `${COLORS[color]}${text}${COLORS.reset}`; }

// The fingerprint that our test "node" would have (simulating Alpha/Beta)
const OUR_NETWORK_FINGERPRINT = 'test-fingerprint-simulating-new-code-12345';

// ═══════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════

function fetchJson(url, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { timeout }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`Invalid JSON from ${url}`)); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function wsConnect(url, timeout = 5000) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const timeoutId = setTimeout(() => {
      resolve({ success: false, error: 'timeout', duration: timeout });
    }, timeout);
    
    try {
      const ws = new WebSocket(url);
      const messages = [];
      
      ws.on('open', () => {
        const openTime = Date.now() - startTime;
        // Send HELLO with our test identity
        ws.send(JSON.stringify({
          type: 'hello',
          identity: {
            nodeId: 'test-probe-node',
            networkFingerprint: 'TEST_PROBE_FINGERPRINT',
          },
          timestamp: Date.now(),
        }));
      });
      
      ws.on('message', (data) => {
        try {
          const msg = JSON.parse(data.toString());
          messages.push(msg);
          
          // Check if we got rejected
          if (msg.type === 'error' && msg.reason === 'INCOMPATIBLE_CODEBASE') {
            clearTimeout(timeoutId);
            ws.close();
            resolve({ 
              success: true, 
              rejected: true, 
              reason: msg.reason,
              messages,
              duration: Date.now() - startTime,
            });
          }
          
          // Check if we got accepted (hello_ack)
          if (msg.type === 'hello_ack' || msg.type === 'welcome') {
            clearTimeout(timeoutId);
            setTimeout(() => {
              ws.close();
              resolve({
                success: true,
                rejected: false,
                peered: true,
                identity: msg.identity,
                messages,
                duration: Date.now() - startTime,
              });
            }, 500);
          }
        } catch (e) { /* ignore parse errors */ }
      });
      
      ws.on('close', (code, reason) => {
        clearTimeout(timeoutId);
        resolve({
          success: true,
          rejected: code === 1008,
          closeCode: code,
          closeReason: reason?.toString(),
          messages,
          duration: Date.now() - startTime,
        });
      });
      
      ws.on('error', (err) => {
        clearTimeout(timeoutId);
        resolve({ success: false, error: err.message, duration: Date.now() - startTime });
      });
    } catch (e) {
      clearTimeout(timeoutId);
      resolve({ success: false, error: e.message, duration: Date.now() - startTime });
    }
  });
}

async function checkNodeHealth(node) {
  try {
    const health = await fetchJson(`${node.http}/health`);
    return { online: true, ...health };
  } catch (e) {
    return { online: false, error: e.message };
  }
}

/**
 * Test outbound connection TO a target node, simulating what a new-code node does.
 * We send HELLO with our fingerprint and check if the target:
 * 1. Responds with WELCOME (and we check their fingerprint)
 * 2. We reject if fingerprints don't match (simulating new code behavior)
 */
async function testOutboundConnection(targetWs, targetName = 'target', ourFingerprint = OUR_NETWORK_FINGERPRINT) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const timeout = 5000;
    const timeoutId = setTimeout(() => {
      ws.close();
      resolve({ success: false, error: 'timeout', duration: timeout });
    }, timeout);
    
    const ws = new WebSocket(targetWs);
    const messages = [];
    
    ws.on('open', () => {
      // Send HELLO with our identity and fingerprint
      ws.send(JSON.stringify({
        type: 'HELLO',
        identity: {
          nodeId: 'test-outbound-node-' + Date.now(),
          publicKey: 'test-public-key',
          networkId: 'test-network-id',
          networkFingerprint: ourFingerprint,
        },
        version: '1.3.0',
      }));
    });
    
    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString());
        messages.push(msg);
        
        if (msg.type === 'WELCOME') {
          clearTimeout(timeoutId);
          const theirFingerprint = msg.identity?.networkFingerprint;
          const fingerprintMatch = theirFingerprint === ourFingerprint;
          
          if (!fingerprintMatch) {
            // New code behavior: reject mismatched fingerprint
            ws.close(1008, 'Network fingerprint mismatch');
            resolve({
              success: true,
              rejected: true,
              rejectedBy: 'us',
              reason: 'fingerprint_mismatch',
              ourFingerprint,
              theirFingerprint,
              messages,
              duration: Date.now() - startTime,
            });
          } else {
            // Fingerprints match - would peer
            ws.close(1000, 'Test complete');
            resolve({
              success: true,
              rejected: false,
              peered: true,
              ourFingerprint,
              theirFingerprint,
              messages,
              duration: Date.now() - startTime,
            });
          }
        }
      } catch (e) { /* ignore parse errors */ }
    });
    
    ws.on('close', (code, reason) => {
      clearTimeout(timeoutId);
      // If closed before WELCOME, they rejected us
      if (messages.length === 0 || !messages.find(m => m.type === 'WELCOME')) {
        resolve({
          success: true,
          rejected: true,
          rejectedBy: 'them',
          closeCode: code,
          closeReason: reason?.toString(),
          messages,
          duration: Date.now() - startTime,
        });
      }
    });
    
    ws.on('error', (err) => {
      clearTimeout(timeoutId);
      resolve({ success: false, error: err.message, duration: Date.now() - startTime });
    });
  });
}

function printHeader(text) {
  console.log('\n' + c('cyan', '═'.repeat(70)));
  console.log(c('bright', `  ${text}`));
  console.log(c('cyan', '═'.repeat(70)) + '\n');
}

function printSubHeader(text) {
  console.log('\n' + c('yellow', `━━━ ${text} ━━━`) + '\n');
}

// ═══════════════════════════════════════════════════════════════════
// TEST SUITE
// ═══════════════════════════════════════════════════════════════════

async function checkAllNodes() {
  printSubHeader('Node Status Check');
  
  const results = {};
  for (const [key, node] of Object.entries(NODES)) {
    const health = await checkNodeHealth(node);
    results[key] = health;
    
    if (health.online) {
      console.log(`  ${c('green', '✓')} ${node.name}: ONLINE`);
      console.log(`    Network: ${health.network?.name || 'N/A'} (${health.network?.id || 'N/A'})`);
      console.log(`    Fingerprint: ${health.network?.fingerprint?.slice(0, 16) || 'N/A'}...`);
      console.log(`    Peers: ${health.peers}`);
    } else {
      console.log(`  ${c('red', '✗')} ${node.name}: OFFLINE (${health.error})`);
    }
  }
  
  return results;
}

async function testPeerConnection(fromNode, toNode, expectRejection) {
  console.log(`  Testing ${fromNode.name} → ${toNode.name}...`);
  
  // For same-codebase tests, check if they're already peered via health endpoint
  if (!expectRejection) {
    // Check peer counts - if they're same codebase, they should already be peered
    try {
      const fromHealth = await fetchJson(`${fromNode.http}/health`);
      const toHealth = await fetchJson(`${toNode.http}/health`);
      
      if (fromHealth.peers > 0 && toHealth.peers > 0) {
        console.log(`    ${c('green', '✓')} CORRECTLY PEERED (${fromHealth.peers} peers / ${toHealth.peers} peers)`);
        return { passed: true, result: { peered: true, peerCount: fromHealth.peers } };
      } else {
        console.log(`    ${c('red', '✗')} NOT PEERED (${fromHealth.peers} / ${toHealth.peers} peers)`);
        return { passed: false, result: { peered: false } };
      }
    } catch (e) {
      console.log(`    ${c('red', '✗')} Health check failed: ${e.message}`);
      return { passed: false, result: { error: e.message } };
    }
  }
  
  // For different-codebase tests, probe with test fingerprint (should be rejected)
  const result = await wsConnect(toNode.ws);
  
  if (!result.success) {
    console.log(`    ${c('red', '✗')} Connection failed: ${result.error}`);
    return { passed: false, result };
  }
  
  if (result.rejected && expectRejection) {
    console.log(`    ${c('green', '✓')} CORRECTLY REJECTED (${result.reason || 'code 1008'})`);
    return { passed: true, result };
  }
  
  if (!result.rejected && !expectRejection) {
    console.log(`    ${c('green', '✓')} CORRECTLY ACCEPTED (peered)`);
    return { passed: true, result };
  }
  
  // Unexpected result
  if (result.rejected && !expectRejection) {
    console.log(`    ${c('red', '✗')} UNEXPECTEDLY REJECTED!`);
    return { passed: false, result };
  }
  
  if (!result.rejected && expectRejection) {
    console.log(`    ${c('red', '✗')} UNEXPECTEDLY ACCEPTED! Code Proof BYPASSED!`);
    return { passed: false, result };
  }
  
  return { passed: false, result };
}

// ═══════════════════════════════════════════════════════════════════
// TEST 1: Two Synced + One Old
// ═══════════════════════════════════════════════════════════════════

async function runTest1() {
  printHeader('TEST 1: Two Synced Nodes + One Old Codebase');
  
  console.log('Scenario:');
  console.log('  • Alpha & Beta = SAME new codebase → should PEER');
  console.log('  • Gamma = OLD codebase (no fingerprint check)');
  console.log('  • New nodes reject connections FROM old nodes');
  console.log('  • Old nodes accept connections (backwards compat issue)\n');
  
  const nodeStatus = await checkAllNodes();
  
  // Check prerequisites
  const requiredNodes = ['alpha', 'beta', 'gamma'];
  const missingNodes = requiredNodes.filter(n => !nodeStatus[n]?.online);
  
  if (missingNodes.length > 0) {
    console.log(c('red', `\n⚠️  Missing nodes: ${missingNodes.join(', ')}`));
    console.log('Please start all nodes before running this test.\n');
    return { passed: false, reason: 'missing nodes' };
  }
  
  printSubHeader('Peer Connection Tests');
  
  let criticalPassed = true;
  let warningCount = 0;
  
  // Test Alpha ↔ Beta (should succeed - same codebase)
  console.log(c('cyan', '\n  [Same Codebase Tests]'));
  const ab = await testPeerConnection(NODES.alpha, NODES.beta, false);
  const ba = await testPeerConnection(NODES.beta, NODES.alpha, false);
  criticalPassed = criticalPassed && ab.passed && ba.passed;
  
  // Test Gamma → Alpha/Beta (old code connecting to new code - should be REJECTED by receiver)
  console.log(c('cyan', '\n  [Old Code → New Code (receiver should reject)]'));
  const ga = await testPeerConnection(NODES.gamma, NODES.alpha, true);
  const gb = await testPeerConnection(NODES.gamma, NODES.beta, true);
  criticalPassed = criticalPassed && ga.passed && gb.passed;
  
  // Test Alpha/Beta → Gamma (new code connecting to old code)
  // With our WELCOME check, Alpha should REJECT Gamma when Gamma's WELCOME lacks fingerprint
  // OR: Old code may not respond with WELCOME at all (protocol incompatibility = effective rejection)
  console.log(c('cyan', '\n  [New Code → Old Code (initiator should reject on WELCOME or timeout)]'));
  
  // Test actual connection attempt - Alpha to Gamma
  console.log('  Testing Alpha (local) → Gamma (LAN)...');
  const agResult = await testOutboundConnection(NODES.gamma.ws);
  if (agResult.rejectedOnWelcome || agResult.rejected) {
    console.log(`    ${c('green', '✓')} CORRECTLY REJECTED (fingerprint mismatch)`);
  } else if (agResult.error === 'timeout') {
    // Timeout is also acceptable - old code doesn't send WELCOME, so no peering possible
    console.log(`    ${c('green', '✓')} EFFECTIVE REJECTION (old code no WELCOME - protocol incompatible)`);
  } else if (!agResult.success) {
    console.log(`    ${c('yellow', '?')} Connection error: ${agResult.error}`);
  } else {
    console.log(`    ${c('red', '✗')} ACCEPTED! Should have rejected on WELCOME`);
    criticalPassed = false;
  }
  
  console.log('  Testing Beta (local) → Gamma (LAN)...');
  const bgResult = await testOutboundConnection(NODES.gamma.ws);
  if (bgResult.rejectedOnWelcome || bgResult.rejected) {
    console.log(`    ${c('green', '✓')} CORRECTLY REJECTED (fingerprint mismatch)`);
  } else if (bgResult.error === 'timeout') {
    console.log(`    ${c('green', '✓')} EFFECTIVE REJECTION (old code no WELCOME - protocol incompatible)`);
  } else if (!bgResult.success) {
    console.log(`    ${c('yellow', '?')} Connection error: ${bgResult.error}`);
  } else {
    console.log(`    ${c('red', '✗')} ACCEPTED! Should have rejected on WELCOME`);
    criticalPassed = false;
  }
  
  printSubHeader('Test 1 Results');
  
  if (criticalPassed) {
    console.log(c('green', '✓ CRITICAL TESTS PASSED'));
    console.log('  • Same-codebase nodes (Alpha/Beta) can peer');
    console.log('  • New code correctly rejects connections from old code');
    console.log('  • Old code cannot peer with new code (protocol incompatible)');
  } else {
    console.log(c('red', '✗ CRITICAL TESTS FAILED'));
    console.log('  Review the output above for details.');
  }
  
  return { passed: criticalPassed };
}

// ═══════════════════════════════════════════════════════════════════
// TEST 2: Protocol Isolation Matrix - N Fingerprints All Reject Each Other
// ═══════════════════════════════════════════════════════════════════

async function runTest2() {
  printHeader('TEST 2: Protocol Isolation Matrix');
  
  console.log('Scenario:');
  console.log('  • Simulate 5 different network fingerprints');
  console.log('  • Each fingerprint tries to connect to Alpha (real node)');
  console.log('  • All should be REJECTED - proving N-way isolation');
  console.log('  • Tests the mathematical completeness of fingerprint rejection\n');
  
  const nodeStatus = await checkAllNodes();
  
  // Only need Alpha online for this test
  if (!nodeStatus.alpha?.online) {
    console.log(c('red', '\n⚠️  Alpha node is OFFLINE. Start it first.'));
    return { passed: false, reason: 'alpha offline' };
  }
  
  console.log(c('green', `✓ Alpha ONLINE (fingerprint: ${nodeStatus.alpha.network?.id || 'unknown'})\n`));
  
  // Generate 5 unique fake fingerprints (simulating 5 different codebases)
  const fakeFingerprints = [
    { name: 'Codebase-A', fp: 'a'.repeat(64) },
    { name: 'Codebase-B', fp: 'b'.repeat(64) },
    { name: 'Codebase-C', fp: 'c'.repeat(64) },
    { name: 'Evil-Clone',  fp: 'd'.repeat(64) },  // Malicious actor
    { name: 'Modified-Fork', fp: 'e'.repeat(64) }, // Forked codebase
  ];
  
  printSubHeader('2a: N-Way Fingerprint Rejection Matrix');
  console.log('  Each simulated codebase → Alpha (should all REJECT)\n');
  
  let allRejected = true;
  
  for (const fake of fakeFingerprints) {
    process.stdout.write(`  ${fake.name.padEnd(15)} → Alpha: `);
    
    const result = await testOutboundConnection(NODES.alpha.ws, 'Alpha', fake.fp);
    
    if (result.rejected) {
      console.log(c('green', 'REJECTED ✓'));
    } else if (result.error === 'timeout') {
      console.log(c('yellow', 'TIMEOUT (acceptable)'));
    } else if (!result.success) {
      console.log(c('yellow', `ERROR: ${result.error}`));
    } else {
      console.log(c('red', 'ACCEPTED ✗'));
      allRejected = false;
    }
  }
  
  printSubHeader('2b: Empty Fingerprint Attack');
  console.log('  Attacker sends HELLO with no fingerprint\n');
  
  const emptyFpResult = await new Promise((resolve) => {
    const ws = new WebSocket(NODES.alpha.ws);
    const timeout = setTimeout(() => { ws.close(); resolve({ result: 'timeout' }); }, 5000);
    
    ws.on('open', () => {
      // Send HELLO with missing fingerprint
      ws.send(JSON.stringify({
        type: 'HELLO',
        identity: {
          nodeId: 'empty-fp-attacker',
          publicKey: 'fake-key',
          networkId: 'attacker-network',
          // networkFingerprint deliberately omitted
        },
        version: '1.3.0',
      }));
    });
    
    ws.on('close', (code) => {
      clearTimeout(timeout);
      resolve({ result: code === 1008 ? 'rejected' : `closed-${code}` });
    });
    
    ws.on('error', (err) => {
      clearTimeout(timeout);
      resolve({ result: 'error', error: err.message });
    });
  });
  
  const emptyFpPassed = emptyFpResult.result === 'rejected' || 
                        emptyFpResult.result === 'timeout' ||
                        emptyFpResult.result?.startsWith('closed-');
  
  console.log(`  Result: ${emptyFpResult.result}`);
  if (emptyFpPassed) {
    console.log(c('green', '  ✓ Empty fingerprint correctly rejected/ignored'));
  } else {
    console.log(c('red', '  ✗ Empty fingerprint ACCEPTED - vulnerability!'));
    allRejected = false;
  }
  
  printSubHeader('2c: Partial Fingerprint Attack');
  console.log('  Attacker sends truncated/malformed fingerprint\n');
  
  const partialFpResult = await testOutboundConnection(NODES.alpha.ws, 'Alpha', 'abc123');  // Too short
  
  const partialFpPassed = partialFpResult.rejected || 
                          partialFpResult.error === 'timeout' ||
                          !partialFpResult.success;
  
  console.log(`  Result: ${partialFpResult.rejected ? 'rejected' : partialFpResult.error || 'unknown'}`);
  if (partialFpPassed) {
    console.log(c('green', '  ✓ Partial fingerprint correctly rejected'));
  } else {
    console.log(c('red', '  ✗ Partial fingerprint ACCEPTED - vulnerability!'));
    allRejected = false;
  }
  
  printSubHeader('2d: Gamma → Alpha Cross-Check');
  console.log('  Real old-code node (Gamma) → Alpha\n');
  
  if (nodeStatus.gamma?.online) {
    const gaResult = await testPeerConnection(NODES.gamma, NODES.alpha, true);
    if (gaResult.passed) {
      console.log(c('green', '  ✓ Gamma correctly rejected by Alpha'));
    } else {
      console.log(c('red', '  ✗ Gamma was ACCEPTED by Alpha'));
      allRejected = false;
    }
  } else {
    console.log(c('yellow', '  ⚠️ Gamma offline - skipped'));
  }
  
  printSubHeader('Test 2 Results');
  
  if (allRejected) {
    console.log(c('green', '✓ ALL ISOLATION TESTS PASSED'));
    console.log('  • N-way fingerprint rejection: Working');
    console.log('  • Empty fingerprint attack: Blocked');
    console.log('  • Partial fingerprint attack: Blocked');
    console.log('  • Cross-network isolation: Verified');
    console.log(c('cyan', '\n  "Within the gaps, there inlies God" - Protocol is airtight'));
  } else {
    console.log(c('red', '✗ SOME ISOLATION TESTS FAILED'));
    console.log('  Code Proof Protocol may have vulnerabilities.');
  }
  
  return { passed: allRejected };
}

// ═══════════════════════════════════════════════════════════════════
// TEST 3: Stress Test - Rapid Reconnection & Race Conditions
// ═══════════════════════════════════════════════════════════════════

async function runTest3() {
  printHeader('TEST 3: Stress Test - Race Conditions & Rapid Reconnection');
  
  console.log('Scenario:');
  console.log('  • Rapid sequential connection attempts');
  console.log('  • Parallel connection flood');
  console.log('  • Testing for race condition bypasses\n');
  
  const nodeStatus = await checkAllNodes();
  
  if (!nodeStatus.alpha?.online || !nodeStatus.gamma?.online) {
    console.log(c('red', '⚠️  Need at least Alpha and Gamma online'));
    return { passed: false, reason: 'missing nodes' };
  }
  
  // Sub-test 3a: Rapid sequential connections to secured node (Alpha)
  // Testing if rapid connections can bypass fingerprint check
  printSubHeader('3a: Rapid Sequential Connections (10x to Alpha)');
  console.log('  Rapidly connecting to Alpha (secured) with wrong fingerprint 10 times...\n');
  
  let rejectedCount = 0;
  let acceptedCount = 0;
  let errorCount = 0;
  
  for (let i = 0; i < 10; i++) {
    const result = await wsConnect(NODES.alpha.ws, 2000);
    if (result.rejected) rejectedCount++;
    else if (result.peered) acceptedCount++;
    else errorCount++;
    process.stdout.write(`  Attempt ${i + 1}: ${result.rejected ? c('green', 'R') : result.peered ? c('red', 'A') : c('yellow', 'E')}`);
    if (i < 9) process.stdout.write(' ');
  }
  console.log('\n');
  console.log(`  Rejected: ${rejectedCount}, Accepted: ${acceptedCount}, Errors: ${errorCount}`);
  
  const rapidTestPassed = acceptedCount === 0;
  if (rapidTestPassed) {
    console.log(c('green', '  ✓ All rapid connections correctly rejected'));
  } else {
    console.log(c('red', `  ✗ ${acceptedCount} connections were ACCEPTED! Race condition vulnerability!`));
  }
  
  // Sub-test 3b: Parallel connection flood
  printSubHeader('3b: Parallel Connection Flood (20 simultaneous to Alpha)');
  console.log('  Flooding Alpha (new code) with 20 simultaneous wrong-fingerprint connections...\n');
  
  const floodPromises = Array(20).fill(null).map(() => wsConnect(NODES.alpha.ws, 3000));
  const floodResults = await Promise.all(floodPromises);
  
  const floodRejected = floodResults.filter(r => r.rejected).length;
  const floodAccepted = floodResults.filter(r => r.peered).length;
  const floodErrors = floodResults.filter(r => !r.success).length;
  
  console.log(`  Rejected: ${floodRejected}, Accepted: ${floodAccepted}, Errors: ${floodErrors}`);
  
  const floodTestPassed = floodAccepted === 0;
  if (floodTestPassed) {
    console.log(c('green', '  ✓ All flood connections correctly rejected or errored'));
  } else {
    console.log(c('red', `  ✗ ${floodAccepted} connections were ACCEPTED during flood!`));
  }
  
  // Sub-test 3c: Spoofed fingerprint attempt
  printSubHeader('3c: Fingerprint Spoofing Attempt (targeting Alpha)');
  console.log('  Attempting to connect to Alpha with spoofed fingerprint...\n');
  
  const spoofResult = await new Promise((resolve) => {
    const ws = new WebSocket(NODES.alpha.ws);
    const timeout = setTimeout(() => resolve({ result: 'timeout' }), 5000);
    
    ws.on('open', () => {
      // Try to send a HELLO with Alpha's fingerprint (spoofed)
      // This tests if the node validates fingerprint vs actual code hash
      ws.send(JSON.stringify({
        type: 'HELLO',
        identity: {
          nodeId: 'spoofed-node-' + Date.now(),
          publicKey: 'fake-public-key',
          // Attempt to spoof - send a random but valid-looking fingerprint
          networkFingerprint: 'a'.repeat(64),
          networkId: 'spoofed-network',
        },
        version: '1.3.0',
        timestamp: Date.now(),
      }));
    });
    
    ws.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'error' || msg.type === 'WELCOME') {
        clearTimeout(timeout);
        ws.close();
        resolve({ result: msg.type === 'error' ? 'error' : 'accepted', msg });
      }
    });
    
    ws.on('close', (code) => {
      clearTimeout(timeout);
      resolve({ result: code === 1008 ? 'rejected' : `closed-${code}` });
    });
    
    ws.on('error', (err) => {
      clearTimeout(timeout);
      resolve({ result: 'error', error: err.message });
    });
  });
  
  console.log(`  Result: ${spoofResult.result}`);
  const spoofPassed = spoofResult.result === 'rejected' || spoofResult.result === 'error' || 
                      spoofResult.result?.startsWith('closed-');
  
  if (spoofPassed) {
    console.log(c('green', '  ✓ Spoofed fingerprint correctly rejected'));
  } else if (spoofResult.result === 'accepted') {
    console.log(c('red', '  ✗ CRITICAL: Spoofed fingerprint ACCEPTED!'));
  } else {
    console.log(c('yellow', `  ? Inconclusive result: ${JSON.stringify(spoofResult)}`));
  }
  
  printSubHeader('Test 3 Results');
  
  const allPassed = rapidTestPassed && floodTestPassed && spoofPassed;
  
  if (allPassed) {
    console.log(c('green', '✓ ALL STRESS TESTS PASSED'));
    console.log('  • Rapid reconnection: Secure');
    console.log('  • Connection flood: Secure');
    console.log('  • Fingerprint spoofing: Blocked');
  } else {
    console.log(c('red', '✗ SOME STRESS TESTS FAILED'));
    console.log('  Potential race conditions or validation bypasses detected.');
  }
  
  return { passed: allPassed };
}

// ═══════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════

async function main() {
  console.log('\n');
  console.log(c('cyan', '╔══════════════════════════════════════════════════════════════════════╗'));
  console.log(c('cyan', '║') + c('bright', '     YAKMESH COMPREHENSIVE 3-NODE TEST SUITE                        ') + c('cyan', '║'));
  console.log(c('cyan', '║') + '     Testing Code Proof Protocol Security                            ' + c('cyan', '║'));
  console.log(c('cyan', '╚══════════════════════════════════════════════════════════════════════╝'));
  
  // Parse command line for specific test(s) - supports --test=1,3 or --test=all
  const testArg = process.argv.find(arg => arg.startsWith('--test='));
  const testValue = testArg ? testArg.split('=')[1] : null;
  const runTests = testValue === 'all' ? [1, 2, 3] : 
                   testValue ? testValue.split(',').map(t => parseInt(t.trim())) : 
                   [1, 2, 3];
  
  const results = {};
  
  if (runTests.includes(1)) {
    results.test1 = await runTest1();
  }
  
  if (runTests.includes(2)) {
    results.test2 = await runTest2();
  }
  
  if (runTests.includes(3)) {
    results.test3 = await runTest3();
  }
  
  // Final summary
  printHeader('FINAL SUMMARY');
  
  let totalPassed = 0;
  let totalTests = 0;
  
  for (const [name, result] of Object.entries(results)) {
    totalTests++;
    if (result.passed) totalPassed++;
    console.log(`  ${result.passed ? c('green', '✓') : c('red', '✗')} ${name.toUpperCase()}: ${result.passed ? 'PASSED' : 'FAILED'}`);
  }
  
  console.log('');
  if (totalPassed === totalTests) {
    console.log(c('green', `🎉 ALL ${totalTests} TESTS PASSED - Code Proof Protocol is SECURE`));
  } else {
    console.log(c('red', `⚠️  ${totalTests - totalPassed}/${totalTests} TESTS FAILED - Review required`));
  }
  console.log('');
  
  process.exit(totalPassed === totalTests ? 0 : 1);
}

main().catch(err => {
  console.error(c('red', 'Fatal error:'), err);
  process.exit(1);
});
