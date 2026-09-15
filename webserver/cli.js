/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This Source Code Form is subject to the terms of the YAKMESH
 * NETWORK ENGINE LICENSE AGREEMENT, v. 1.0. If a copy of that
 * license agreement was not distributed with this file, You can
 * find a link to the license at https://yakmesh.dev/license
 *
 * This Source Code Form is "Incompatible With Secondary Licenses",
 * as defined by the YAKMESH NETWORK ENGINE LICENSE AGREEMENT, v. 1.0.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
/**
 * Yakmesh Web Server CLI Commands
 * 
 * Adds web server management to the yakmesh CLI
 */

import { YakmeshWebServer } from './index.js';
import { createLogger } from '../utils/logger.js';

const log = createLogger('webserver:cli');

/**
 * Register web server commands with Commander
 */
export function registerWebCommands(program) {
  const web = program
    .command('web')
    .description('Manage the embedded web server');
  
  web
    .command('start')
    .description('Start the web server')
    .option('-p, --port <port>', 'HTTP port', '8080')
    .option('-r, --root <path>', 'Document root', './htdocs')
    .option('-d, --domain <domain>', 'Domain for auto-HTTPS')
    .option('--https', 'Enable automatic HTTPS via Let\'s Encrypt')
    .option('--php', 'Enable PHP support (requires php-cgi)')
    .action(async (options) => {
      const server = new YakmeshWebServer({
        port: parseInt(options.port),
        root: options.root,
        domain: options.domain,
        autoHttps: options.https,
        phpEnabled: options.php
      });
      
      await server.start();
      
      // Keep running
      process.on('SIGINT', async () => {
        await server.stop();
        process.exit(0);
      });
    });
  
  web
    .command('install')
    .description('Download and install Caddy web server')
    .action(async () => {
      const server = new YakmeshWebServer();
      await server.install();
    });
  
  web
    .command('status')
    .description('Check web server status')
    .action(() => {
      const server = new YakmeshWebServer();
      log.info('Web server status', { installed: server.isInstalled(), binaryPath: server.caddyBinary });
    });
  
  return web;
}

export default registerWebCommands;
