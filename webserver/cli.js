/**
 * Yakmesh Web Server CLI Commands
 * 
 * Adds web server management to the yakmesh CLI
 */

import { YakmeshWebServer } from './index.js';

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
      console.log('Caddy installed:', server.isInstalled());
      console.log('Binary path:', server.caddyBinary);
    });
  
  return web;
}

export default registerWebCommands;
