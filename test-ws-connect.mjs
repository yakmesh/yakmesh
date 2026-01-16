/**
 * Live Peer Connection Test - Using correct WS port 9001
 */

const WebSocket = (await import('ws')).default;

const REMOTE_NODE = 'ws://WIN-LQH9ULSNBFU:9001';
const LOCAL_NODE = 'ws://localhost:9001';

async function testConnection(url, name) {
  return new Promise((resolve) => {
    console.log('Connecting to ' + name + ' (' + url + ')...');
    
    const timeout = setTimeout(() => {
      console.log('  ❌ Timeout');
      resolve({ success: false, name, error: 'timeout' });
    }, 5000);
    
    try {
      const ws = new WebSocket(url);
      
      ws.on('open', () => {
        clearTimeout(timeout);
        console.log('  ✅ Connected!');
        
        // Send a HELLO message like the mesh protocol expects
        const msg = JSON.stringify({
          type: 'hello',
          identity: { nodeId: 'test-probe' },
          timestamp: Date.now()
        });
        ws.send(msg);
        console.log('  → Sent HELLO');
        
        setTimeout(() => {
          ws.close();
          resolve({ success: true, name });
        }, 2000);
      });
      
      ws.on('message', (data) => {
        console.log('  ← Received: ' + data.toString().slice(0, 150));
      });
      
      ws.on('error', (err) => {
        clearTimeout(timeout);
        console.log('  ❌ Error: ' + err.message);
        resolve({ success: false, name, error: err.message });
      });
      
    } catch (e) {
      clearTimeout(timeout);
      console.log('  ❌ Failed: ' + e.message);
      resolve({ success: false, name, error: e.message });
    }
  });
}

console.log('=== PEER CONNECTION TEST (WebSocket port 9001) ===\n');

const results = [];
results.push(await testConnection(LOCAL_NODE, 'Local'));
console.log('');
results.push(await testConnection(REMOTE_NODE, 'Remote'));

console.log('\n--- RESULTS ---');
results.forEach(r => console.log(r.name + ':', r.success ? '✅ Connected' : '❌ ' + r.error));

if (results.every(r => r.success)) {
  console.log('\n⚠️  BOTH NODES CONNECTED - Code Proof is NOT preventing communication!');
}

process.exit(0);
