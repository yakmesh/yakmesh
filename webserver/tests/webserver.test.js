/**
 * WebServer Module Tests — YakmeshWebServer + registerWebCommands
 *
 * Tests config, Caddyfile generation, status, and CLI wiring.
 * Does NOT start Caddy or download binaries.
 *
 * @module webserver/tests/webserver.test
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert';
import { join } from 'path';

import { YakmeshWebServer, startWebServer } from '../index.js';
import { registerWebCommands } from '../cli.js';

console.log('\n🌐  WebServer Module Tests\n');
console.log('='.repeat(60));

// =============================================================================
// YakmeshWebServer — construction + defaults
// =============================================================================

describe('YakmeshWebServer', () => {
  describe('constructor defaults', () => {
    let ws;
    before(() => { ws = new YakmeshWebServer(); });

    it('sets default port to 8080', () => {
      assert.strictEqual(ws.config.port, 8080);
    });

    it('sets default httpsPort to 8443', () => {
      assert.strictEqual(ws.config.httpsPort, 8443);
    });

    it('sets default root to ./htdocs', () => {
      assert.strictEqual(ws.config.root, './htdocs');
    });

    it('defaults autoHttps to false', () => {
      assert.strictEqual(ws.config.autoHttps, false);
    });

    it('defaults domain to null', () => {
      assert.strictEqual(ws.config.domain, null);
    });

    it('defaults phpEnabled to false', () => {
      assert.strictEqual(ws.config.phpEnabled, false);
    });

    it('defaults phpPort to 9000', () => {
      assert.strictEqual(ws.config.phpPort, 9000);
    });

    it('is not running initially', () => {
      assert.strictEqual(ws.running, false);
    });

    it('process is null initially', () => {
      assert.strictEqual(ws.process, null);
    });
  });

  describe('constructor with custom config', () => {
    it('overrides port', () => {
      const ws = new YakmeshWebServer({ port: 9090 });
      assert.strictEqual(ws.config.port, 9090);
    });

    it('overrides domain', () => {
      const ws = new YakmeshWebServer({ domain: 'example.com' });
      assert.strictEqual(ws.config.domain, 'example.com');
    });

    it('overrides phpEnabled', () => {
      const ws = new YakmeshWebServer({ phpEnabled: true });
      assert.strictEqual(ws.config.phpEnabled, true);
    });
  });

  // ===========================================================================
  // _getCaddyBinaryPath
  // ===========================================================================

  describe('_getCaddyBinaryPath', () => {
    it('returns path in caddyPath dir', () => {
      const ws = new YakmeshWebServer({ caddyPath: '/custom/bin' });
      // On Windows path.join converts / to \, so check with platform sep
      assert.ok(ws.caddyBinary.includes('custom') && ws.caddyBinary.includes('bin'));
    });

    it('appends .exe on win32', () => {
      if (process.platform === 'win32') {
        const ws = new YakmeshWebServer();
        assert.ok(ws.caddyBinary.endsWith('.exe'));
      } else {
        const ws = new YakmeshWebServer();
        assert.ok(!ws.caddyBinary.endsWith('.exe'));
      }
    });
  });

  // ===========================================================================
  // _getPlatformKey
  // ===========================================================================

  describe('_getPlatformKey', () => {
    it('returns platform-arch string', () => {
      const ws = new YakmeshWebServer();
      const key = ws._getPlatformKey();
      assert.ok(key.includes('-'), 'should be platform-arch format');
      assert.ok(key.includes(process.platform), 'should include current platform');
      assert.ok(key.includes(process.arch), 'should include current arch');
    });
  });

  // ===========================================================================
  // isInstalled
  // ===========================================================================

  describe('isInstalled', () => {
    it('returns boolean', () => {
      const ws = new YakmeshWebServer({ caddyPath: '/nonexistent' });
      assert.strictEqual(typeof ws.isInstalled(), 'boolean');
    });

    it('returns false for non-existent path', () => {
      const ws = new YakmeshWebServer({ caddyPath: '/definitely/not/here' });
      assert.strictEqual(ws.isInstalled(), false);
    });
  });

  // ===========================================================================
  // generateCaddyfile
  // ===========================================================================

  describe('generateCaddyfile', () => {
    it('generates local config without domain', () => {
      const ws = new YakmeshWebServer({ port: 4000, root: './www' });
      const cf = ws.generateCaddyfile();
      assert.ok(cf.includes(':4000'), 'should include port');
      assert.ok(cf.includes('./www'), 'should include root');
      assert.ok(cf.includes('file_server'), 'should include file_server');
      assert.ok(cf.includes('auto_https off'), 'should disable auto_https');
    });

    it('generates domain config with HTTPS', () => {
      const ws = new YakmeshWebServer({
        domain: 'mesh.example.com',
        autoHttps: true,
        root: './public',
      });
      const cf = ws.generateCaddyfile();
      assert.ok(cf.includes('mesh.example.com'), 'should include domain');
      assert.ok(cf.includes('./public'), 'should include root');
      assert.ok(!cf.includes('auto_https off'), 'should NOT disable auto_https');
    });

    it('includes PHP block when phpEnabled', () => {
      const ws = new YakmeshWebServer({ phpEnabled: true, phpPort: 9001 });
      const cf = ws.generateCaddyfile();
      assert.ok(cf.includes('*.php'), 'should include PHP matcher');
      assert.ok(cf.includes('9001'), 'should include PHP port');
    });

    it('excludes PHP block when phpEnabled is false', () => {
      const ws = new YakmeshWebServer({ phpEnabled: false });
      const cf = ws.generateCaddyfile();
      assert.ok(!cf.includes('*.php'), 'should NOT include PHP matcher');
    });

    it('includes security headers', () => {
      const ws = new YakmeshWebServer();
      const cf = ws.generateCaddyfile();
      assert.ok(cf.includes('X-Content-Type-Options nosniff'));
      assert.ok(cf.includes('X-Frame-Options DENY'));
    });
  });

  // ===========================================================================
  // status
  // ===========================================================================

  describe('status', () => {
    it('returns expected shape', () => {
      const ws = new YakmeshWebServer({ port: 7070, root: './tmp' });
      const s = ws.status();
      assert.strictEqual(s.running, false);
      assert.strictEqual(s.port, 7070);
      assert.strictEqual(s.root, './tmp');
      assert.strictEqual(typeof s.caddyInstalled, 'boolean');
      assert.strictEqual(s.pid, null);
    });
  });
});

// =============================================================================
// startWebServer export
// =============================================================================

describe('startWebServer export', () => {
  it('is a function', () => {
    assert.strictEqual(typeof startWebServer, 'function');
  });
});

// =============================================================================
// registerWebCommands (CLI wiring)
// =============================================================================

describe('registerWebCommands', () => {
  it('is a function', () => {
    assert.strictEqual(typeof registerWebCommands, 'function');
  });

  it('registers web command on a Commander-like program', () => {
    // Minimal Commander mock
    const commands = [];
    const cmd = {
      command(name) {
        const sub = {
          _name: name,
          description() { return sub; },
          option() { return sub; },
          action() { return sub; },
          command(n) {
            const sub2 = {
              _name: n,
              description() { return sub2; },
              option() { return sub2; },
              action() { return sub2; },
            };
            commands.push(sub2);
            return sub2;
          },
        };
        commands.push(sub);
        return sub;
      },
    };

    registerWebCommands(cmd);
    const names = commands.map(c => c._name);
    assert.ok(names.includes('web'), 'Should register "web" command');
    assert.ok(names.includes('start'), 'Should register "start" subcommand');
    assert.ok(names.includes('install'), 'Should register "install" subcommand');
    assert.ok(names.includes('status'), 'Should register "status" subcommand');
  });
});
