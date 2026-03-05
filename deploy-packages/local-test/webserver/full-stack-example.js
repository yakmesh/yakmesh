/**
 * Yakmesh Full Stack Example
 * 
 * Demonstrates running both the mesh network AND web server together
 * This is the "self-hosting" experience - one command to run everything
 */

import { YakmeshNode } from '../server/index.js';
import { YakmeshWebServer } from '../webserver/index.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('webserver:fullstack');

async function main() {
  log.info('Starting YAKMESH Full Stack - Mesh Network + Web Server');

  // 1. Start the mesh node
  const meshNode = new YakmeshNode({
    name: 'My Yakmesh Node',
    port: 9001,
    enableDashboard: true,
    dashboardPort: 3080
  });

  // 2. Start the web server
  const webServer = new YakmeshWebServer({
    port: 8080,
    root: './htdocs',
    phpEnabled: false  // Set true if you have php-cgi
  });

  // Start both
  await meshNode.start();
  await webServer.start();

  log.info('All services running', {
    meshNode: 'ws://localhost:9001',
    dashboard: 'http://localhost:3000',
    webServer: 'http://localhost:8080'
  });

  // Graceful shutdown
  process.on('SIGINT', async () => {
    log.info('Shutting down...');
    await webServer.stop();
    await meshNode.stop();
    process.exit(0);
  });
}

main().catch(console.error);
