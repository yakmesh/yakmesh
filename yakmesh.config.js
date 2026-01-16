// Alpha node - connects to Gamma on LAN
export default {
  nodeId: 'alpha-lan-test',
  server: { port: 3001, host: '0.0.0.0' },
  mesh: { port: 9002, host: '0.0.0.0' },
  peers: ['ws://192.168.1.178:9001'],
  dataDir: './test-nodes/data-alpha'
};
