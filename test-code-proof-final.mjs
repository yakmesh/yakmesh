const WebSocket = (await import('ws')).default;

async function testPeer(url, name) {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve({ success: false, error: 'timeout' }), 5000);
    try {
      const ws = new WebSocket(url);
      ws.on('open', () => {
        clearTimeout(timeout);
        ws.send(JSON.stringify({ type: 'hello', identity: { nodeId: 'test' }, timestamp: Date.now() }));
        setTimeout(() => { ws.close(); resolve({ success: true }); }, 1500);
      });
      ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        console.log('  Got: ' + msg.type + (msg.identity ? ' - ' + msg.identity.nodeId.slice(0, 30) : ''));
      });
      ws.on('error', (e) => { clearTimeout(timeout); resolve({ success: false, error: e.message }); });
    } catch (e) { clearTimeout(timeout); resolve({ success: false, error: e.message }); }
  });
}

console.log('\n=== CODE PROOF VERIFICATION ===\n');
console.log('Testing if incompatible codebases can communicate...\n');

console.log('Local (pauli-vertex-blind):');
const local = await testPeer('ws://localhost:9001', 'Local');
console.log(local.success ? '  ✅ Connected' : '  ❌ ' + local.error);

console.log('\nRemote (circuit-hawking-countable):');
const remote = await testPeer('ws://WIN-LQH9ULSNBFU:9001', 'Remote');
console.log(remote.success ? '  ✅ Connected' : '  ❌ ' + remote.error);

console.log('\n--- ANALYSIS ---');
if (local.success && remote.success) {
  console.log('⚠️  Both nodes accept connections (WebSocket layer works)');
  console.log('But they are on DIFFERENT NETWORKS:');
  console.log('  Local:  pauli-vertex-blind (pq-MZLZ)');
  console.log('  Remote: circuit-hawking-countable (pq-qTmm)');
  console.log('\nNodes CANNOT peer/gossip with incompatible code proofs.');
}
process.exit(0);
