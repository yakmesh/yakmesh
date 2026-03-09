/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
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
    dashboard: 'http://localhost:3080',
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
