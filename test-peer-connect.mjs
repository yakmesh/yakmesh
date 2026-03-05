/**
 * Live Peer Connection Test
 * Verify if nodes with different codebases CAN actually connect
 */

// Test direct WebSocket connection to remote node
const WebSocket = (await import('ws')).default;

const REMOTE_NODE = 'ws://WIN-LQH9ULSNBFU:3080/ws';
const LOCAL_NODE = 'ws://localhost:3080/ws';

async function testConnection(url, name) {
  return new Promise((resolve) => {
    console.log('Connecting to ' + name + '...');

    try {
      const ws = new WebSocket(url);

      ws.on('open', () => {
        console.log('  ✅ Connected to ' + name);

        // Send a test gossip message
        const msg = JSON.stringify({
          type: 'hello',
          from: 'test-node',
          data: { test: true }
        });
        ws.send(msg);
        console.log('  → Sent test message');

        setTimeout(() => {
          ws.close();
          resolve({ success: true, name });
        }, 2000);
      });

      ws.on('message', (data) => {
        console.log('  ← Received: ' + data.toString().slice(0, 100));
      });

      ws.on('error', (err) => {
        console.log('  ❌ Error: ' + err.message);
        resolve({ success: false, name, error: err.message });
      });

    } catch (e) {
      console.log('  ❌ Failed: ' + e.message);
      resolve({ success: false, name, error: e.message });
    }
  });
}

console.log('=== PEER CONNECTION TEST ===\n');

const remote = await testConnection(REMOTE_NODE, 'Remote Node (WIN-LQH9ULSNBFU)');
console.log('');
const local = await testConnection(LOCAL_NODE, 'Local Node');

console.log('\n--- CONCLUSION ---\n');

if (remote.success && local.success) {
  console.log('⚠️  BOTH NODES ARE ACCEPTING CONNECTIONS!');
  console.log('This proves that Code Proof is NOT preventing communication');
  console.log('between nodes with different codebases.');
  console.log('\nFIX REQUIRED: Code hash must include ALL critical files.');
} else {
  console.log('At least one node is not accepting connections.');
  console.log('Results:');
  console.log('  Remote:', remote.success ? '✅' : '❌', remote.error || '');
  console.log('  Local:', local.success ? '✅' : '❌', local.error || '');
}

process.exit(0);
