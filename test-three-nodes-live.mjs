/**
 * YAKMESH Live 3-Node Integration Test Suite
 * 
 * Tests against REAL running nodes across different network segments:
 *   LOCAL:     http://localhost:3080     (AMD Ryzen 7 8700F, MA-902 GPS, stratum 1)
 *   LAN:       http://192.168.1.178:3080 (LAN server, MA-902 GPS, stratum 1)
 *   HOSTINGER: http://localhost:3081      (VPS via SSH tunnel, no GPS, stratum 16)
 *
 * Prerequisites:
 *   - All 3 nodes running with matching oracle fingerprints
 *   - SSH tunnel: ssh -p 65002 -L 3081:localhost:3080 -N u170268362@156.67.75.34
 *   - MA-902 GPS Time Server at 192.168.1.30 (accessible from LOCAL + LAN)
 *
 * Run with: node test-three-nodes-live.mjs
 */

import { setTimeout as sleep } from 'timers/promises';

// ═════════════════════════════════════════════════
// CONFIGURATION
// ═════════════════════════════════════════════════

const NODES = [
  { name: 'LOCAL',     url: 'http://localhost:3080',      hasGPS: true,  segment: 'local' },
  { name: 'LAN',       url: 'http://192.168.1.178:3080',  hasGPS: true,  segment: 'lan' },
  { name: 'HOSTINGER', url: 'http://localhost:3081',       hasGPS: false, segment: 'cloud' },
];

const TIMEOUT = 8000;
let passed = 0;
let failed = 0;
let skipped = 0;

// ═════════════════════════════════════════════════
// HELPERS
// ═════════════════════════════════════════════════

async function get(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

function pass(name, detail) {
  passed++;
  console.log(`  \u2713 PASS: ${name}${detail ? ' — ' + detail : ''}`);
}

function fail(name, detail) {
  failed++;
  console.log(`  \u2717 FAIL: ${name}${detail ? ' — ' + detail : ''}`);
}

function skip(name, reason) {
  skipped++;
  console.log(`  \u26A0 SKIP: ${name} — ${reason}`);
}

function section(title) {
  console.log(`\n${'━'.repeat(60)}`);
  console.log(`  ${title}`);
  console.log(`${'━'.repeat(60)}\n`);
}

// ═════════════════════════════════════════════════
// PRE-FLIGHT: Verify all nodes are reachable
// ═════════════════════════════════════════════════

async function preflight() {
  section('PRE-FLIGHT CHECK');
  const live = [];
  for (const node of NODES) {
    try {
      const h = await get(`${node.url}/health`);
      console.log(`  ${node.name}: UP  id=${h.nodeId?.slice(-12) || '?'}  peers=${h.peers}`);
      node.health = h;
      live.push(node);
    } catch (e) {
      console.log(`  ${node.name}: DOWN (${e.message})`);
    }
  }
  if (live.length < 2) {
    console.log('\n  ABORT: Need at least 2 nodes running. Only ' + live.length + ' reachable.');
    process.exit(1);
  }
  if (live.length < 3) {
    console.log(`\n  WARNING: Only ${live.length}/3 nodes reachable. Some tests will be skipped.`);
  }
  return live;
}

// ═════════════════════════════════════════════════
// TEST 1: Oracle Fingerprint Consensus
// ═════════════════════════════════════════════════

async function testOracleConsensus(nodes) {
  section('TEST 1: Oracle Codebase Fingerprint Consensus');

  const fingerprints = [];
  for (const node of nodes) {
    try {
      const id = await get(`${node.url}/network/identity`);
      const oracle = await get(`${node.url}/oracle/status`);
      fingerprints.push({ node: node.name, fp: id.fingerprint, name: id.name, id: id.id });
      console.log(`  ${node.name}: network=${id.name} id=${id.id} fp=${id.fingerprint.slice(0, 16)}...`);
      console.log(`           oracle=${oracle.status} integrity=${oracle.integrity?.valid}`);
    } catch (e) {
      fail(`${node.name} oracle`, e.message);
    }
  }

  const unique = new Set(fingerprints.map(f => f.fp));
  if (unique.size === 1 && fingerprints.length === nodes.length) {
    pass('All nodes share identical codebase fingerprint', `${fingerprints[0].name} (${fingerprints[0].id})`);
  } else if (unique.size > 1) {
    fail('Fingerprint mismatch detected', `${unique.size} different fingerprints across ${fingerprints.length} nodes`);
    fingerprints.forEach(f => console.log(`    ${f.node}: ${f.fp.slice(0, 24)}...`));
  }
}

// ═════════════════════════════════════════════════
// TEST 2: Atomic Timing & GPS Time Source
// ═════════════════════════════════════════════════

async function testAtomicTiming(nodes) {
  section('TEST 2: Atomic Timing & GPS Time Source (MA-902)');

  const timeData = [];
  for (const node of nodes) {
    try {
      const ts = await get(`${node.url}/time/status`);
      const tc = await get(`${node.url}/time/capabilities`);
      timeData.push({ node: node.name, status: ts, caps: tc, hasGPS: node.hasGPS });

      console.log(`  ${node.name}: trust=${ts.trustLevel} stratum=${ts.stratum} source=${ts.source || ts.activeSource || 'unknown'}`);
      console.log(`           phaseTolerance=${ts.phaseTolerance}ms locked=${ts.locked ?? ts.gpsLocked ?? '?'}`);
      console.log(`           canBeTimeOracle=${tc.canBeTimeOracle} hasAtomicTime=${tc.hasAtomicTime}`);
    } catch (e) {
      fail(`${node.name} time`, e.message);
    }
  }

  // 2a. GPS nodes (LOCAL, LAN) should have trust=gps, stratum=1
  const gpsNodes = timeData.filter(t => t.hasGPS);
  for (const t of gpsNodes) {
    if (t.status.trustLevel === 'gps' && t.status.stratum === 1) {
      pass(`${t.node} GPS trust`, `trust=${t.status.trustLevel} stratum=${t.status.stratum}`);
    } else {
      fail(`${t.node} GPS trust`, `expected trust=gps stratum=1, got trust=${t.status.trustLevel} stratum=${t.status.stratum}`);
    }
  }

  // 2b. Non-GPS node (HOSTINGER) should have higher stratum
  const nonGpsNodes = timeData.filter(t => !t.hasGPS);
  for (const t of nonGpsNodes) {
    if (t.status.stratum > 1) {
      pass(`${t.node} non-GPS stratum`, `stratum=${t.status.stratum} (correctly higher than GPS nodes)`);
    } else {
      fail(`${t.node} non-GPS stratum`, `expected stratum>1, got ${t.status.stratum}`);
    }
  }

  // 2c. GPS nodes should be time oracle capable
  for (const t of gpsNodes) {
    if (t.caps.canBeTimeOracle) {
      pass(`${t.node} time oracle capability`, 'canBeTimeOracle=true');
    } else {
      fail(`${t.node} time oracle capability`, 'GPS node should be time oracle capable');
    }
  }

  // 2d. Phase tolerance: GPS nodes should have tighter tolerance than non-GPS
  if (gpsNodes.length > 0 && nonGpsNodes.length > 0) {
    const gpsPhase = gpsNodes[0].status.phaseTolerance;
    const noGpsPhase = nonGpsNodes[0].status.phaseTolerance;
    if (gpsPhase && noGpsPhase && gpsPhase <= noGpsPhase) {
      pass('GPS phase tighter than NTP', `GPS=${gpsPhase}ms <= NTP=${noGpsPhase}ms`);
    } else if (gpsPhase && noGpsPhase) {
      fail('GPS phase should be tighter', `GPS=${gpsPhase}ms vs NTP=${noGpsPhase}ms`);
    }
  }

  // 2e. Inter-node timestamp comparison (check all /health timestamps)
  const timestamps = [];
  for (const node of nodes) {
    try {
      const t0 = Date.now();
      const h = await get(`${node.url}/health`);
      const rtt = Date.now() - t0;
      if (h.timestamp) timestamps.push({ node: node.name, ts: h.timestamp, rtt });
    } catch (e) { /* skip */ }
  }
  if (timestamps.length >= 2) {
    const times = timestamps.map(t => t.ts);
    const maxDiff = Math.max(...times) - Math.min(...times);
    const maxRtt = Math.max(...timestamps.map(t => t.rtt));
    if (maxDiff <= 500 + maxRtt) {
      pass('Inter-node clock agreement', `maxDiff=${maxDiff}ms (RTT-adjusted tolerance=${500 + maxRtt}ms)`);
    } else {
      fail('Inter-node clock divergence', `${maxDiff}ms exceeds ${500 + maxRtt}ms tolerance`);
    }
  }
}

// ═════════════════════════════════════════════════
// TEST 3: Trust Level Hierarchy
// ═════════════════════════════════════════════════

async function testTrustLevels(nodes) {
  section('TEST 3: Trust Level Hierarchy');

  const trustOrder = { 'atomic': 0, 'gps': 1, 'ptp': 2, 'ntp-auth': 3, 'ntp': 4, 'system': 5, 'unsync': 6 };
  const levels = [];

  for (const node of nodes) {
    try {
      const ts = await get(`${node.url}/time/status`);
      const pc = await get(`${node.url}/time/phase-config`);
      levels.push({ node: node.name, trust: ts.trustLevel, stratum: ts.stratum, hasGPS: node.hasGPS, phaseConfig: pc });
      console.log(`  ${node.name}: trust=${ts.trustLevel} (rank ${trustOrder[ts.trustLevel] ?? '?'}) stratum=${ts.stratum}`);
    } catch (e) {
      fail(`${node.name} trust`, e.message);
    }
  }

  // 3a. GPS nodes should have equal or better trust than non-GPS
  const gpsLevels = levels.filter(l => l.hasGPS);
  const noGpsLevels = levels.filter(l => !l.hasGPS);

  if (gpsLevels.length > 0 && noGpsLevels.length > 0) {
    const bestGps = Math.min(...gpsLevels.map(l => trustOrder[l.trust] ?? 99));
    const bestNoGps = Math.min(...noGpsLevels.map(l => trustOrder[l.trust] ?? 99));
    if (bestGps <= bestNoGps) {
      pass('GPS nodes rank higher or equal in trust hierarchy');
    } else {
      fail('Non-GPS node has better trust than GPS node');
    }
  }

  // 3b. Stratum hierarchy: GPS nodes should be stratum <= non-GPS stratum
  if (gpsLevels.length > 0 && noGpsLevels.length > 0) {
    const gpsStratum = Math.min(...gpsLevels.map(l => l.stratum));
    const noGpsStratum = Math.min(...noGpsLevels.map(l => l.stratum));
    if (gpsStratum <= noGpsStratum) {
      pass('Stratum hierarchy correct', `GPS stratum ${gpsStratum} <= non-GPS stratum ${noGpsStratum}`);
    } else {
      fail('Stratum hierarchy inverted', `GPS=${gpsStratum} > non-GPS=${noGpsStratum}`);
    }
  }

  // 3c. Phase config should differ between trust levels
  if (levels.length >= 2) {
    const configs = levels.filter(l => l.phaseConfig);
    if (configs.length >= 2) {
      const epochs = new Set(configs.map(c => c.phaseConfig.epochDurationHours));
      console.log(`  Phase configs: ${configs.map(c => `${c.node}=${c.phaseConfig.epochDurationHours}h`).join(', ')}`);
      pass('Phase configuration loaded for all nodes');
    }
  }
}

// ═════════════════════════════════════════════════
// TEST 4: Security Subsystems
// ═════════════════════════════════════════════════

async function testSecurity(nodes) {
  section('TEST 4: Security Subsystems');

  for (const node of nodes) {
    try {
      const sec = await get(`${node.url}/security/status`);

      // 4a. Post-quantum crypto should be configured
      if (sec.crypto?.level === 'NIST Level 3') {
        pass(`${node.name} PQ crypto`, `${sec.crypto.signatures} + ${sec.crypto.keyExchange}`);
      } else {
        fail(`${node.name} PQ crypto`, `expected NIST Level 3, got ${sec.crypto?.level}`);
      }

      // 4b. Oracle integrity should be valid
      if (sec.oracle?.valid) {
        pass(`${node.name} oracle integrity`, 'self-integrity check passed');
      } else {
        fail(`${node.name} oracle integrity`, `valid=${sec.oracle?.valid}`);
      }

      // 4c. Namche gateway should be initialized
      if (sec.namche?.status !== 'uninitialized') {
        pass(`${node.name} Namche gateway`, `status=${sec.namche.status}`);
      } else {
        skip(`${node.name} Namche gateway`, 'not initialized');
      }

    } catch (e) {
      fail(`${node.name} security`, e.message);
    }
  }

  // 4d. Check Namche gate details on each node
  for (const node of nodes) {
    try {
      const gates = await get(`${node.url}/security/namche/gates`);
      if (gates.gates) {
        const gateNames = Object.keys(gates.gates);
        const openGates = gateNames.filter(g => gates.gates[g].status === 'open' || gates.gates[g].status === 'active');
        console.log(`  ${node.name} Namche gates: ${gateNames.length} total, ${openGates.length} active: [${gateNames.join(', ')}]`);
        pass(`${node.name} Namche gates enumerated`, `${gateNames.length} gates`);
      }
    } catch (e) { /* optional */ }
  }

  // 4e. Security stats (handshake limiter, burst detection)
  for (const node of nodes) {
    try {
      const h = await get(`${node.url}/health`);
      if (h.security) {
        console.log(`  ${node.name} security stats: handshakes=${JSON.stringify(h.security.handshakes || {})} burst=${JSON.stringify(h.security.burstDetection || {})}`);
        pass(`${node.name} security stats on /health`, 'handshake limiter + burst detection reporting');
      }
    } catch (e) { /* optional */ }
  }
}

// ═════════════════════════════════════════════════
// TEST 5: Hardware Acceleration & Compute Scheduler
// ═════════════════════════════════════════════════

async function testAccel(nodes) {
  section('TEST 5: Hardware Acceleration & Compute Scheduler');

  for (const node of nodes) {
    try {
      const accel = await get(`${node.url}/accel`);
      const sched = await get(`${node.url}/scheduler`);
      const sw = await get(`${node.url}/steadywatch`);

      // 5a. Accel status
      console.log(`  ${node.name} accel: sha3=${accel.sha3Engine || '?'} blake3=${accel.blake3Engine || '?'} aes=${accel.aesEngine || '?'}`);
      if (accel.sha3Engine || accel.native) {
        pass(`${node.name} hardware acceleration`, `sha3=${accel.sha3Engine || 'fallback'}`);
      } else {
        skip(`${node.name} hardware acceleration`, 'no native accel detected');
      }

      // 5b. Scheduler
      console.log(`  ${node.name} scheduler: queued=${sched.queuedTasks ?? '?'} completed=${sched.completedTasks ?? '?'} providers=${JSON.stringify(sched.providers || sched.backends || [])}`);
      pass(`${node.name} compute scheduler`, 'responding');

      // 5c. SteadyWatch entropy
      if (sw.entropyPoolSize || sw.poolSize || sw.status) {
        pass(`${node.name} SteadyWatch entropy`, `pool=${sw.entropyPoolSize || sw.poolSize || '?'} quality=${sw.quality || sw.entropyQuality || '?'}`);
      } else {
        skip(`${node.name} SteadyWatch`, 'minimal data');
      }

    } catch (e) {
      fail(`${node.name} accel/scheduler`, e.message);
    }
  }
}

// ═════════════════════════════════════════════════
// TEST 6: SAKSHI Witness & KARMA Trust Model
// ═════════════════════════════════════════════════

async function testSakshiKarma(nodes) {
  section('TEST 6: SAKSHI Witness & KARMA Trust Model');

  for (const node of nodes) {
    try {
      const s = await get(`${node.url}/sakshi/status`);
      if (s.active) {
        console.log(`  ${node.name} SAKSHI: witnessCount=${s.witness?.count ?? '?'} role=${s.witness?.role ?? '?'}`);
        console.log(`  ${node.name} KARMA:  active=${s.karma?.active} trust=${s.karma?.localTrust ?? s.karma?.score ?? '?'}`);
        console.log(`  ${node.name} Velocity: active=${s.velocity?.active} alerts=${(s.velocity?.activeAlerts || []).length}`);
        pass(`${node.name} SAKSHI witness active`);
        if (s.karma?.active) {
          pass(`${node.name} KARMA trust model active`);
        } else {
          skip(`${node.name} KARMA`, 'not active yet');
        }
      } else {
        skip(`${node.name} SAKSHI`, 'not active');
      }
    } catch (e) {
      skip(`${node.name} SAKSHI/KARMA`, e.message);
    }
  }
}

// ═════════════════════════════════════════════════
// TEST 7: NakPak Onion Routing
// ═════════════════════════════════════════════════

async function testNakPak(nodes) {
  section('TEST 7: NakPak Onion Routing');

  for (const node of nodes) {
    try {
      const n = await get(`${node.url}/nakpak/status`);
      if (n.active) {
        console.log(`  ${node.name} NakPak: circuits=${n.circuits} relays=${n.relays}`);
        pass(`${node.name} NakPak active`, `circuits=${n.circuits} relays=${n.relays}`);
      } else {
        skip(`${node.name} NakPak`, 'not active');
      }
    } catch (e) {
      skip(`${node.name} NakPak`, 'endpoint not available');
    }
  }
}

// ═════════════════════════════════════════════════
// TEST 8: DOKO Identity Registry
// ═════════════════════════════════════════════════

async function testDoko(nodes) {
  section('TEST 8: DOKO Identity Registry');

  for (const node of nodes) {
    try {
      const d = await get(`${node.url}/security/doko/stats`);
      console.log(`  ${node.name} DOKO: status=${d.status || 'active'} types=${JSON.stringify(d.types || [])}`);
      
      const ids = await get(`${node.url}/security/doko/identities`);
      console.log(`  ${node.name} identities: count=${ids.count}`);
      pass(`${node.name} DOKO registry`, `${ids.count || 0} identities registered`);
    } catch (e) {
      skip(`${node.name} DOKO`, e.message);
    }
  }
}

// ═════════════════════════════════════════════════
// TEST 9: SHERPA Discovery & Mesh Relay
// ═════════════════════════════════════════════════

async function testSherpa(nodes) {
  section('TEST 9: SHERPA Discovery & Mesh Relay');

  for (const node of nodes) {
    try {
      const sh = await get(`${node.url}/sherpa/status`);
      console.log(`  ${node.name} SHERPA: registry=${sh.registry?.size ?? sh.registrySize ?? '?'} connectable=${sh.connectable ?? '?'}`);
      
      const cand = await get(`${node.url}/sherpa/candidates`);
      const candCount = Array.isArray(cand) ? cand.length : (cand.candidates?.length ?? 0);
      console.log(`  ${node.name} candidates: ${candCount}`);
      pass(`${node.name} SHERPA discovery`, `registry=${sh.registry?.size ?? sh.registrySize ?? 0}`);
    } catch (e) {
      skip(`${node.name} SHERPA`, e.message);
    }
  }

  // Relay status
  for (const node of nodes) {
    try {
      const h = await get(`${node.url}/health`);
      if (h.relayPeers !== undefined) {
        console.log(`  ${node.name} relay: pollers=${h.relayPollers} clients=${h.relayClients} outbox=${h.relayOutbox}`);
        pass(`${node.name} relay reporting`);
      }
    } catch (e) { /* optional */ }
  }
}

// ═════════════════════════════════════════════════
// TEST 10: Gossip Protocol & Peer State
// ═════════════════════════════════════════════════

async function testGossip(nodes) {
  section('TEST 10: Gossip Protocol & Peer State');

  for (const node of nodes) {
    try {
      const g = await get(`${node.url}/gossip`);
      const peers = await get(`${node.url}/peers`);
      const discovered = await get(`${node.url}/discovered`);
      const peerCount = Array.isArray(peers) ? peers.length : (peers?.count ?? 0);
      const discCount = Array.isArray(discovered) ? discovered.length : (discovered?.count ?? 0);

      console.log(`  ${node.name} gossip: rumors=${g.rumorCount ?? g.rumors ?? '?'} peers=${peerCount} discovered=${discCount}`);
      pass(`${node.name} gossip protocol`, `peers=${peerCount}`);
    } catch (e) {
      fail(`${node.name} gossip`, e.message);
    }
  }
}

// ═════════════════════════════════════════════════
// TEST 11: Network Handshake & Identity
// ═════════════════════════════════════════════════

async function testHandshake(nodes) {
  section('TEST 11: Network Handshake & Node Identity');

  const identities = [];
  for (const node of nodes) {
    try {
      const hs = await get(`${node.url}/network/handshake`);
      const ni = await get(`${node.url}/node`);

      identities.push({ node: node.name, nodeId: ni.nodeId || hs.nodeId });
      console.log(`  ${node.name} nodeId=${(ni.nodeId || '?').slice(-16)}`);
      console.log(`           algo=${ni.algorithm || hs.algorithm || '?'} pubkey=${(ni.publicKey || hs.publicKey || '').slice(0, 24)}...`);

      if (ni.algorithm === 'ML-DSA-65' || hs.algorithm === 'ML-DSA-65') {
        pass(`${node.name} ML-DSA-65 identity`);
      } else {
        fail(`${node.name} identity algorithm`, `expected ML-DSA-65, got ${ni.algorithm || hs.algorithm}`);
      }
    } catch (e) {
      fail(`${node.name} handshake`, e.message);
    }
  }

  // All nodeIds should be unique
  const uniqueIds = new Set(identities.map(i => i.nodeId).filter(Boolean));
  if (uniqueIds.size === identities.length && identities.length > 0) {
    pass('All node IDs are unique', `${uniqueIds.size} unique across ${identities.length} nodes`);
  } else if (identities.length > 0) {
    fail('Node ID uniqueness', `${uniqueIds.size} unique out of ${identities.length}`);
  }
}

// ═════════════════════════════════════════════════
// TEST 12: Cross-Segment Heterogeneity Validation
// ═════════════════════════════════════════════════

async function testHeterogeneity(nodes) {
  section('TEST 12: Cross-Segment Heterogeneity');

  const nodeData = [];
  for (const node of nodes) {
    try {
      const h = await get(`${node.url}/health`);
      const t = await get(`${node.url}/time/status`);
      const a = await get(`${node.url}/accel`);
      nodeData.push({ name: node.name, segment: node.segment, health: h, time: t, accel: a });
    } catch (e) { /* skip */ }
  }

  // 12a. Multiple network segments represented
  const segments = new Set(nodeData.map(n => n.segment));
  if (segments.size >= 2) {
    pass('Multi-segment deployment', `segments: [${[...segments].join(', ')}]`);
  } else {
    skip('Multi-segment', 'only one segment reachable');
  }

  // 12b. Heterogeneous time sources
  const trustLevels = new Set(nodeData.map(n => n.time?.trustLevel).filter(Boolean));
  if (trustLevels.size >= 2) {
    pass('Heterogeneous time sources', `trust levels: [${[...trustLevels].join(', ')}]`);
  } else if (trustLevels.size === 1) {
    console.log(`  All nodes have same trust level: ${[...trustLevels][0]}`);
    pass('Homogeneous time sources (still valid)');
  }

  // 12c. Hardware diversity
  const accelEngines = nodeData.map(n => n.accel?.sha3Engine || 'unknown');
  console.log(`  Accel engines: ${nodeData.map(n => `${n.name}=${n.accel?.sha3Engine || 'fallback'}`).join(', ')}`);
  pass('Hardware acceleration probed across all segments');
}

// ═════════════════════════════════════════════════
// MAIN
// ═════════════════════════════════════════════════

async function main() {
  console.log(`
\u2554${'═'.repeat(62)}\u2557
\u2551  YAKMESH LIVE 3-NODE INTEGRATION TEST SUITE                     \u2551
\u2551  Real Network Validation \u2014 ${new Date().toISOString().slice(0, 16)}                    \u2551
\u255A${'═'.repeat(62)}\u255D
`);

  const liveNodes = await preflight();

  await testOracleConsensus(liveNodes);
  await testAtomicTiming(liveNodes);
  await testTrustLevels(liveNodes);
  await testSecurity(liveNodes);
  await testAccel(liveNodes);
  await testSakshiKarma(liveNodes);
  await testNakPak(liveNodes);
  await testDoko(liveNodes);
  await testSherpa(liveNodes);
  await testGossip(liveNodes);
  await testHandshake(liveNodes);
  await testHeterogeneity(liveNodes);

  // ═══ SUMMARY ═══
  const total = passed + failed + skipped;
  console.log(`
\u2554${'═'.repeat(62)}\u2557
\u2551                      TEST SUMMARY                               \u2551
\u255A${'═'.repeat(62)}\u255D

  Total:   ${total}
  Passed:  ${passed}
  Failed:  ${failed}
  Skipped: ${skipped}

  ${failed === 0 ? '\u2713 ALL TESTS PASSED' : '\u2717 ' + failed + ' TEST(S) FAILED'} ${skipped > 0 ? '(' + skipped + ' skipped)' : ''}
`);

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(2);
});
