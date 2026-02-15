/**
 * CLI Module Tests — command registration and structure
 *
 * Tests that the CLI module properly defines Commander commands,
 * options, and the version constant. Does NOT execute any commands
 * or start a server.
 *
 * @module cli/tests/cli.test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

console.log('\n⌨️  CLI Module Tests\n');
console.log('='.repeat(60));

// We cannot safely `import` cli/index.js because it calls program.parse()
// at module load time. Instead, test by reading the source and verifying
// structural expectations — a lightweight static analysis approach.

const cliSource = readFileSync(join(__dirname, '..', 'index.js'), 'utf8');

// =============================================================================
// Version constant
// =============================================================================

describe('CLI version', () => {
  it('defines a VERSION constant', () => {
    assert.ok(cliSource.includes("const VERSION"), 'Should define VERSION');
  });

  it('version matches semver pattern', () => {
    const match = cliSource.match(/const VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/);
    assert.ok(match, 'VERSION should be a semver string');
    assert.ok(match[1].split('.').length === 3, 'Semver should have 3 parts');
  });
});

// =============================================================================
// Command registration
// =============================================================================

describe('CLI commands', () => {
  it('registers init command', () => {
    assert.ok(cliSource.includes(".command('init')"), 'Should have init command');
  });

  it('registers start command', () => {
    assert.ok(cliSource.includes(".command('start')"), 'Should have start command');
  });

  it('registers status command', () => {
    assert.ok(cliSource.includes(".command('status')"), 'Should have status command');
  });

  it('registers peers command', () => {
    assert.ok(cliSource.includes(".command('peers')"), 'Should have peers command');
  });

  it('registers info command', () => {
    assert.ok(cliSource.includes(".command('info')"), 'Should have info command');
  });

  it('registers join command', () => {
    assert.ok(cliSource.includes(".command('join"), 'Should have join command');
  });

  it('registers open command', () => {
    assert.ok(cliSource.includes(".command('open"), 'Should have open command');
  });

  it('registers protocol command group', () => {
    assert.ok(cliSource.includes(".command('protocol')"), 'Should have protocol command');
  });

  it('registers protocol subcommands', () => {
    assert.ok(cliSource.includes("'register'"), 'protocol register');
    assert.ok(cliSource.includes("'unregister'"), 'protocol unregister');
    assert.ok(cliSource.includes("'test"), 'protocol test');
  });

  it('registers bookmark subcommands', () => {
    assert.ok(cliSource.includes("'bookmark'"), 'bookmark command');
    assert.ok(cliSource.includes("'add"), 'bookmark add');
    assert.ok(cliSource.includes("'list'"), 'bookmark list');
    assert.ok(cliSource.includes("'remove"), 'bookmark remove');
  });
});

// =============================================================================
// Command options
// =============================================================================

describe('CLI options', () => {
  it('init has --name option', () => {
    assert.ok(cliSource.includes("--name <name>"), 'init should have --name');
  });

  it('init has --port option', () => {
    assert.ok(cliSource.includes("--port <port>"), 'init should have --port');
  });

  it('init has --region option', () => {
    assert.ok(cliSource.includes("--region <region>"), 'init should have --region');
  });

  it('init has --ws-port option', () => {
    assert.ok(cliSource.includes("--ws-port <port>"), 'init should have --ws-port');
  });

  it('init has --bootstrap option', () => {
    assert.ok(cliSource.includes("--bootstrap <urls>"), 'init should have --bootstrap');
  });

  it('start has --config option', () => {
    assert.ok(cliSource.includes("--config <path>"), 'start should have --config');
  });

  it('start has --daemon option', () => {
    assert.ok(cliSource.includes("--daemon"), 'start should have --daemon');
  });
});

// =============================================================================
// Architecture expectations
// =============================================================================

describe('CLI architecture', () => {
  it('uses Commander', () => {
    assert.ok(cliSource.includes("from 'commander'"), 'Should import commander');
  });

  it('uses chalk for output', () => {
    assert.ok(cliSource.includes("from 'chalk'"), 'Should import chalk');
  });

  it('calls program.parse()', () => {
    assert.ok(cliSource.includes('program.parse()'), 'Should parse arguments');
  });

  it('sets program version', () => {
    assert.ok(cliSource.includes('.version(VERSION)'), 'Should set version');
  });

  it('defines showBanner function', () => {
    assert.ok(cliSource.includes('function showBanner'), 'Should define banner');
  });

  it('handles SIGINT for graceful shutdown', () => {
    assert.ok(cliSource.includes('SIGINT'), 'Should handle SIGINT');
  });

  it('handles SIGTERM for graceful shutdown', () => {
    assert.ok(cliSource.includes('SIGTERM'), 'Should handle SIGTERM');
  });
});

// =============================================================================
// Default port convention
// =============================================================================

describe('CLI defaults', () => {
  it('uses port 3000 as default', () => {
    assert.ok(cliSource.includes("'3000'"), 'Default port should be 3000');
  });

  it('uses 9001 as default WebSocket port', () => {
    assert.ok(cliSource.includes("'9001'"), 'Default WS port should be 9001');
  });

  it('node name defaults to My Yakmesh Node', () => {
    assert.ok(cliSource.includes("'My Yakmesh Node'"), 'Default node name');
  });

  it('region defaults to local', () => {
    const match = cliSource.match(/--region.*?'local'/);
    assert.ok(match, 'Default region should be local');
  });
});
